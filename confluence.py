#!/usr/bin/env python3

import argparse
import json
import logging
import os
import subprocess
import requests
import tempfile
import time
from datetime import datetime

def setup_logging(verbose):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=level
    )

def load_config(config_path):
    """Load configuration from a JSON file."""
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to load config file {config_path}: {e}")
        return {}

class ConfluenceSecretScanner:
    def __init__(self, token, base_url, trufflehog_path="trufflehog", output_file=None, args=None):
        """Initialize the Confluence secret scanner."""
        self.token = token
        self.base_url = base_url.rstrip('/')
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self.trufflehog_path = trufflehog_path
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logger = logging.getLogger(__name__)
        self.output_file = output_file
        self.args = args

    def get_spaces(self):
        """Fetch all accessible spaces."""
        url = f"{self.base_url}/rest/api/space"
        spaces = []
        while url:
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                spaces.extend(data["results"])
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.5)  # Add delay to avoid rate limits
            except requests.RequestException as e:
                self.logger.error(f"Failed to fetch spaces: {e}")
                break
        return spaces

    def get_space_by_key(self, key):
        """Fetch a specific space by its key."""
        url = f"{self.base_url}/rest/api/space/{key}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch space with key '{key}': {e}")
            return None

    def get_content_in_space(self, space_key, content_type):
        """Fetch all content of a specific type in a space."""
        url = f"{self.base_url}/rest/api/content"
        params = {"spaceKey": space_key, "type": content_type, "expand": "body.storage,version"}
        content = []
        while url:
            try:
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                data = response.json()
                content.extend(data["results"])
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.5)  # Add delay to avoid rate limits
                params = None  # Clear params after first request
            except requests.RequestException as e:
                self.logger.error(f"Failed to fetch {content_type} in space {space_key}: {e}")
                break
        return content

    def get_comments(self, content_id):
        """Fetch comments for a given content ID."""
        url = f"{self.base_url}/rest/api/content/{content_id}/child/comment"
        comments = []
        while url:
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                comments.extend(data["results"])
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.5)  # Add delay to avoid rate limits
            except requests.RequestException as e:
                self.logger.error(f"Failed to fetch comments for content {content_id}: {e}")
                break
        return comments

    def get_attachments(self, content_id):
        """Fetch attachments for a given content ID."""
        url = f"{self.base_url}/rest/api/content/{content_id}/child/attachment"
        attachments = []
        while url:
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                attachments.extend(data["results"])
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.5)  # Add delay to avoid rate limits
            except requests.RequestException as e:
                self.logger.error(f"Failed to fetch attachments for content {content_id}: {e}")
                break
        return attachments

    def get_version_content(self, content_id, version):
        """Fetch the content of a specific version of a page or blog post."""
        url = f"{self.base_url}/rest/api/content/{content_id}?version={version}&expand=body.storage"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()["body"]["storage"]["value"]
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch version {version} of content {content_id}: {e}")
            return ""

    def download_attachment(self, attachment):
        """Download an attachment to a temporary file."""
        if not attachment['title'].endswith(('.txt', '.pdf', '.docx', '.json')):
            self.logger.debug(f"Skipping non-text attachment: {attachment['title']}")
            return None
        download_url = f"{self.base_url}{attachment['_links']['download']}"
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir.name)
        try:
            response = requests.get(download_url, headers=self.headers, stream=True)
            response.raise_for_status()
            with open(temp_file.name, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            return temp_file.name
        except requests.RequestException as e:
            self.logger.error(f"Failed to download attachment {attachment['title']}: {e}")
            os.remove(temp_file.name)
            return None

    def scan_text(self, text):
        """Scan text content with TruffleHog v3."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=self.temp_dir.name) as temp_file:
            temp_file.write(text)
            temp_file_path = temp_file.name
        try:
            result = subprocess.run(
                [self.trufflehog_path, "filesystem", temp_file_path, "--json"],
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout:
                findings = [json.loads(line) for line in result.stdout.strip().splitlines()]
                for finding in findings:
                    yield finding
        except subprocess.CalledProcessError as e:
            self.logger.error(f"TruffleHog scan failed for text content: {e}")
        finally:
            os.remove(temp_file_path)

    def scan_file(self, file_path):
        """Scan a file with TruffleHog v3."""
        try:
            result = subprocess.run(
                [self.trufflehog_path, "filesystem", file_path, "--json"],
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout:
                findings = [json.loads(line) for line in result.stdout.strip().splitlines()]
                for finding in findings:
                    yield finding
        except subprocess.CalledProcessError as e:
            self.logger.error(f"TruffleHog scan failed for file {file_path}: {e}")

    def get_content_url(self, content):
        """Get the full URL of a content item (page or blog post)."""
        relative_url = content["_links"]["webui"]
        return f"{self.base_url}{relative_url}"

    def process_content(self, content, space_key):
        """Process a content item, scanning its versions, comments, and attachments."""
        content_id = content["id"]
        content_type = content["type"]
        title = content["title"]
        url = self.get_content_url(content)

        # Scan all versions
        current_version = content["version"]["number"]
        self.logger.debug(f"Scanning {content_type} {title} with {current_version} versions")
        for version in range(1, current_version + 1):
            version_content = self.get_version_content(content_id, version)
            if version_content:
                for finding in self.scan_text(version_content):
                    finding.update({
                        "space_key": space_key,
                        "content_type": content_type,
                        "content_id": content_id,
                        "version": version,
                        "title": title,
                        "url": url
                    })
                    self._output_finding(finding)

        # Scan comments with error handling for missing 'body'
        comments = self.get_comments(content_id)
        for comment in comments:
            try:
                comment_body = comment["body"]["storage"]["value"]
            except KeyError as e:
                self.logger.warning(f"Skipping comment {comment.get('id', 'unknown')} due to missing key: {e}")
                continue
            for finding in self.scan_text(comment_body):
                finding.update({
                    "space_key": space_key,
                    "content_type": "comment",
                    "content_id": comment["id"],
                    "parent_content_id": content_id,
                    "title": f"Comment on {title}",
                    "url": url
                })
                self._output_finding(finding)

        # Scan attachments
        attachments = self.get_attachments(content_id)
        for attachment in attachments:
            file_path = self.download_attachment(attachment)
            if file_path:
                for finding in self.scan_file(file_path):
                    finding.update({
                        "space_key": space_key,
                        "content_type": "attachment",
                        "attachment_id": attachment["id"],
                        "title": attachment["title"],
                        "url": url
                    })
                    self._output_finding(finding)
                os.remove(file_path)

    def _output_finding(self, finding):
        """Output a finding to the console or file."""
        if self.output_file:
            self.output_file.write(json.dumps(finding) + "\n")
        else:
            self.logger.info(
                f"Found {finding['DetectorName']}: {finding['Raw']} (Verified: {finding['Verified']}) "
                f"in {finding['content_type']} '{finding['title']}' at {finding['url']}"
            )

    def scan_space(self, space):
        """Scan a single Confluence space for secrets."""
        space_key = space["key"]
        self.logger.info(f"Scanning space: {space_key}")

        # Scan space description
        description = space.get("description", {}).get("plain", {}).get("value", "")
        if description:
            for finding in self.scan_text(description):
                finding.update({
                    "space_key": space_key,
                    "content_type": "space_description",
                    "title": f"Description of space {space_key}",
                    "url": f"{self.base_url}/spaces/{space_key}"
                })
                self._output_finding(finding)

        # Scan pages
        pages = self.get_content_in_space(space_key, "page")
        for page in pages:
            self.process_content(page, space_key)

        # Scan blog posts
        blogs = self.get_content_in_space(space_key, "blogpost")
        for blog in blogs:
            self.process_content(blog, space_key)

    def run(self):
        """Run the secret scan across all or specified spaces."""
        if self.args.space_keys:
            spaces_to_scan = []
            for key in self.args.space_keys:
                space = self.get_space_by_key(key)
                if space:
                    spaces_to_scan.append(space)
                else:
                    self.logger.error(f"Space with key '{key}' not found or inaccessible.")
            if not spaces_to_scan:
                self.logger.error("No valid spaces to scan. Exiting.")
                return
        else:
            spaces_to_scan = self.get_spaces()

        for space in spaces_to_scan:
            self.scan_space(space)

        self.logger.info("Scan completed.")
        self.temp_dir.cleanup()

def main():
    parser = argparse.ArgumentParser(
        description="ConfluenceSecretScanner: Scan Confluence for secrets using TruffleHog v3."
    )
    parser.add_argument("--token", help="Confluence Personal Access Token")
    parser.add_argument("--url", help="Confluence base URL (e.g., https://mycompany.atlassian.net/wiki)")
    parser.add_argument("--trufflehog-path", default="trufflehog", help="Path to TruffleHog v3 binary")
    parser.add_argument("--config", help="Path to config JSON file", default=None)
    parser.add_argument("--output", help="Path to output file for findings in JSON format")
    parser.add_argument("--space-keys", nargs='+', help="Specify one or more Confluence space keys to scan (e.g., SPACE1 SPACE2)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    setup_logging(args.verbose)

    # Load config only if provided, otherwise rely on args/env
    config = {}
    if args.config:
        config = load_config(args.config)

    token = args.token or config.get("token") or os.getenv("CONFLUENCE_USER_TOKEN")
    url = args.url or config.get("url")
    trufflehog_path = args.trufflehog_path or config.get("trufflehog_path", "trufflehog")

    if not token:
        logging.error("Confluence token is required. Set via --token, config file, or CONFLUENCE_USER_TOKEN env var.")
        return
    if not url:
        logging.error("Confluence URL is required. Set via --url or config file.")
        return

    if args.output:
        with open(args.output, "w") as output_file:
            scanner = ConfluenceSecretScanner(token, url, trufflehog_path, output_file, args)
            scanner.run()
    else:
        scanner = ConfluenceSecretScanner(token, url, trufflehog_path, args=args)
        scanner.run()

if __name__ == "__main__":
    main()