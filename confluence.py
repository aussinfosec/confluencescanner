#!/usr/bin/env python3

import argparse
import json
import logging
import os
import subprocess
import requests
import tempfile

def setup_logging(verbose):
    """
    Configure logging based on verbosity level.

    Args:
        verbose (bool): If True, set logging to DEBUG; otherwise, INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=level
    )

def load_config(config_path):
    """
    Load configuration from a JSON file.

    Args:
        config_path (str): Path to the config file.

    Returns:
        dict: Configuration dictionary, or empty dict if loading fails.
    """
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to load config file {config_path}: {e}")
        return {}

class ConfluenceSecretScanner:
    def __init__(self, token, base_url, trufflehog_path="trufflehog", output_file=None):
        """
        Initialize the Confluence secret scanner.

        Args:
            token (str): Confluence Personal Access Token for authentication.
            base_url (str): Base URL of the Confluence instance (e.g., https://mycompany.atlassian.net/wiki).
            trufflehog_path (str): Path to the TruffleHog v3 binary.
            output_file (file object, optional): File object to write JSON findings to.
        """
        self.token = token
        self.base_url = base_url.rstrip('/')
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self.trufflehog_path = trufflehog_path
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logger = logging.getLogger(__name__)
        self.output_file = output_file

    def fetch_all(self, url, params=None):
        """
        Fetch all results from a paginated Confluence API endpoint.

        Args:
            url (str): Initial API endpoint URL.
            params (dict, optional): Query parameters for the first request.

        Yields:
            dict: Individual items from the API response.
        """
        while url:
            try:
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                data = response.json()
                for item in data["results"]:
                    yield item
                url = data["_links"].get("next")
                params = None  # Only use params for the first request
            except requests.RequestException as e:
                self.logger.error(f"Failed to fetch from {url}: {e}")
                break

    def get_spaces(self):
        """Fetch all accessible spaces, including their descriptions."""
        url = f"{self.base_url}/rest/api/space?expand=description.plain"
        return list(self.fetch_all(url))

    def get_content_in_space(self, space_key, content_type):
        """
        Fetch all content of a specific type in a space.

        Args:
            space_key (str): Key of the space to scan.
            content_type (str): Type of content ("page" or "blogpost").

        Returns:
            list: List of content items.
        """
        url = f"{self.base_url}/rest/api/content"
        params = {"spaceKey": space_key, "type": content_type, "expand": "body.storage,version"}
        return list(self.fetch_all(url, params))

    def get_comments(self, content_id):
        """
        Fetch comments for a given content ID.

        Args:
            content_id (str): ID of the content (page or blog post).

        Returns:
            list: List of comment objects.
        """
        url = f"{self.base_url}/rest/api/content/{content_id}/child/comment?expand=body.storage"
        return list(self.fetch_all(url))

    def get_attachments(self, content_id):
        """
        Fetch attachments for a given content ID.

        Args:
            content_id (str): ID of the content (page or blog post).

        Returns:
            list: List of attachment objects.
        """
        url = f"{self.base_url}/rest/api/content/{content_id}/child/attachment"
        return list(self.fetch_all(url))

    def get_properties(self, content_id):
        """
        Fetch properties for a given content ID.

        Args:
            content_id (str): ID of the content (page or blog post).

        Returns:
            list: List of property objects.
        """
        url = f"{self.base_url}/rest/api/content/{content_id}/property"
        return list(self.fetch_all(url))

    def get_version_content(self, content_id, version):
        """
        Fetch the content of a specific version of a page or blog post.

        Args:
            content_id (str): ID of the content.
            version (int): Version number to fetch.

        Returns:
            str: Storage format content of the version.
        """
        url = f"{self.base_url}/rest/api/content/{content_id}?version={version}&expand=body.storage"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()["body"]["storage"]["value"]
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch version {version} of content {content_id}: {e}")
            return ""

    def download_attachment(self, attachment):
        """
        Download an attachment to a temporary file.

        Args:
            attachment (dict): Attachment object from the API.

        Returns:
            str: Path to the downloaded file, or None if download fails.
        """
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir.name)
        download_url = f"{self.base_url}{attachment['_links']['download']}"
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
        """
        Scan text content with TruffleHog v3.

        Args:
            text (str): Text content to scan.

        Yields:
            dict: TruffleHog findings.
        """
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
        """
        Scan a file with TruffleHog v3.

        Args:
            file_path (str): Path to the file to scan.

        Yields:
            dict: TruffleHog findings.
        """
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
        """
        Get the full URL of a content item (page or blog post).

        Args:
            content (dict): Content object from the API.

        Returns:
            str: Full URL to the content.
        """
        relative_url = content["_links"]["webui"]
        return f"{self.base_url}{relative_url}"

    def get_space_url(self, space):
        """
        Get the full URL of a space.

        Args:
            space (dict): Space object from the API.

        Returns:
            str: Full URL to the space.
        """
        relative_url = space["_links"]["webui"]
        return f"{self.base_url}{relative_url}"

    def process_content(self, content, space_key):
        """
        Process a content item, scanning its versions, comments, attachments, and properties.

        Args:
            content (dict): Content object (page or blog post).
            space_key (str): Key of the space containing the content.
        """
        content_id = content["id"]
        content_type = content["type"]  # "page" or "blogpost"
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

        # Scan comments
        comments = self.get_comments(content_id)
        for comment in comments:
            comment_body = comment["body"]["storage"]["value"]
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

        # Scan properties
        properties = self.get_properties(content_id)
        for prop in properties:
            prop_value = json.dumps(prop["value"])
            for finding in self.scan_text(prop_value):
                finding.update({
                    "space_key": space_key,
                    "content_type": "property",
                    "property_key": prop["key"],
                    "title": f"Property {prop['key']} on {title}",
                    "url": url
                })
                self._output_finding(finding)

    def _output_finding(self, finding):
        """
        Output a finding to the console or file.

        Args:
            finding (dict): The finding to output.
        """
        if self.output_file:
            self.output_file.write(json.dumps(finding) + "\n")
        else:
            self.logger.info(
                f"Found {finding['DetectorName']}: {finding['Raw']} (Verified: {finding['Verified']}) "
                f"in {finding['content_type']} '{finding['title']}' at {finding['url']}"
            )

    def run(self):
        """Run the secret scan across all accessible spaces and content types."""
        self.logger.info("Starting Confluence secret scan...")
        spaces = self.get_spaces()
        if not spaces:
            self.logger.warning("No spaces found or accessible.")
            return

        for space in spaces:
            space_key = space["key"]
            space_url = self.get_space_url(space)
            self.logger.debug(f"Processing space {space_key}")

            # Scan space description
            description = space.get("description", {}).get("plain", {}).get("value", "")
            if description:
                for finding in self.scan_text(description):
                    finding.update({
                        "space_key": space_key,
                        "content_type": "space_description",
                        "title": f"Description of space {space_key}",
                        "url": space_url
                    })
                    self._output_finding(finding)

            # Scan pages and blog posts
            for content_type in ["page", "blogpost"]:
                contents = self.get_content_in_space(space_key, content_type)
                for content in contents:
                    self.process_content(content, space_key)

        self.logger.info("Scan completed.")
        self.temp_dir.cleanup()

def main():
    """Parse arguments and run the scanner."""
    parser = argparse.ArgumentParser(
        description="Scan Confluence for secrets using TruffleHog v3."
    )
    parser.add_argument("--token", help="Confluence Personal Access Token")
    parser.add_argument("--url", help="Confluence base URL (e.g., https://mycompany.atlassian.net/wiki)")
    parser.add_argument("--trufflehog-path", default="trufflehog", help="Path to TruffleHog v3 binary")
    parser.add_argument("--config", default="config.json", help="Path to config JSON file")
    parser.add_argument("--output", help="Path to output file for findings in JSON format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    # Load config from file, override with CLI args or env vars
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
            scanner = ConfluenceSecretScanner(token, url, trufflehog_path, output_file)
            scanner.run()
    else:
        scanner = ConfluenceSecretScanner(token, url, trufflehog_path)
        scanner.run()

if __name__ == "__main__":
    main()