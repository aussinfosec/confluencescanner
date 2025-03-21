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
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

def setup_logging(verbose):
    """Configure logging based on verbosity."""
    level = logging.INFO if not verbose else logging.DEBUG  # Default to INFO (only findings) unless verbose
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

def get_text_snippet(text, secret, context_length=50):
    """Extract a snippet of text surrounding the secret for context."""
    if not text or not secret:
        return "N/A"
    secret_start = text.find(secret)
    if secret_start == -1:
        return "N/A"
    
    start = max(0, secret_start - context_length)
    end = min(len(text), secret_start + len(secret) + context_length)
    snippet = text[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet.replace("\n", " ").strip()

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
        if self.args.verbose:
            self.logger.debug(f"Created root temporary directory: {self.temp_dir.name}")

    def get_spaces(self):
        """Fetch all accessible spaces."""
        url = f"{self.base_url}/rest/api/space"
        spaces = []
        while url:
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code == 429:
                    if self.args.verbose:
                        self.logger.warning("Rate limit exceeded. Waiting before retry...")
                    time.sleep(60)
                    continue
                response.raise_for_status()
                data = response.json()
                spaces.extend(data["results"])
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.1)  # Reduced delay
            except requests.RequestException as e:
                if self.args.verbose:
                    self.logger.error(f"Failed to fetch spaces: {e}")
                break
        return spaces

    def get_space_by_key(self, key):
        """Fetch a specific space by its key."""
        url = f"{self.base_url}/rest/api/space/{key}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 429:
                if self.args.verbose:
                    self.logger.warning("Rate limit exceeded. Waiting before retry...")
                time.sleep(60)
                return self.get_space_by_key(key)  # Retry
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            if self.args.verbose:
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
                if response.status_code == 429:
                    if self.args.verbose:
                        self.logger.warning("Rate limit exceeded. Waiting before retry...")
                    time.sleep(60)
                    continue
                response.raise_for_status()
                data = response.json()
                content.extend(data["results"])
                if self.args.verbose:
                    self.logger.debug(f"Found {len(data['results'])} {content_type} items in space {space_key}")
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.1)  # Reduced delay
                params = None  # Clear params after first request
            except requests.RequestException as e:
                if self.args.verbose:
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
                if response.status_code == 429:
                    if self.args.verbose:
                        self.logger.warning("Rate limit exceeded. Waiting before retry...")
                    time.sleep(60)
                    continue
                response.raise_for_status()
                data = response.json()
                comments.extend(data["results"])
                if self.args.verbose:
                    self.logger.debug(f"Found {len(data['results'])} comments for content {content_id}")
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.1)  # Reduced delay
            except requests.RequestException as e:
                if self.args.verbose:
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
                if response.status_code == 429:
                    if self.args.verbose:
                        self.logger.warning("Rate limit exceeded. Waiting before retry...")
                    time.sleep(60)
                    continue
                response.raise_for_status()
                data = response.json()
                attachments.extend(data["results"])
                if self.args.verbose:
                    self.logger.debug(f"Found {len(data['results'])} attachments for content {content_id}")
                url = data.get("_links", {}).get("next")
                if url:
                    url = f"{self.base_url}{url}"
                time.sleep(0.1)  # Reduced delay
            except requests.RequestException as e:
                if self.args.verbose:
                    self.logger.error(f"Failed to fetch attachments for content {content_id}: {e}")
                break
        return attachments

    @lru_cache(maxsize=100)
    def get_version_content(self, content_id, version):
        """Fetch the content of a specific version of a page or blog post."""
        url = f"{self.base_url}/rest/api/content/{content_id}?version={version}&expand=body.storage"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 429:
                if self.args.verbose:
                    self.logger.warning("Rate limit exceeded. Waiting before retry...")
                time.sleep(60)
                return self.get_version_content(content_id, version)  # Retry
            response.raise_for_status()
            return response.json()["body"]["storage"]["value"]
        except requests.RequestException as e:
            if self.args.verbose:
                self.logger.error(f"Failed to fetch version {version} of content {content_id}: {e}")
            return ""

    def download_attachment(self, attachment):
        """Download an attachment to a temporary file, ensuring thorough scanning of all possible content."""
        image_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp')
        if attachment['title'].lower().endswith(image_extensions):
            if self.args.verbose:
                self.logger.debug(f"Skipping image attachment: {attachment['title']}")
            return None
        text_extensions = ('.txt', '.pdf', '.docx', '.json', '.html', '.xml', '.csv', '.md', '.xlsx', '.doc', '.zip', '.rar', '.7z')
        download_url = f"{self.base_url}{attachment['_links']['download']}"
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir.name)
        try:
            response = requests.get(download_url, headers=self.headers, stream=True)
            if response.status_code == 429:
                if self.args.verbose:
                    self.logger.warning("Rate limit exceeded. Waiting before retry...")
                time.sleep(60)
                return self.download_attachment(attachment)  # Retry
            response.raise_for_status()
            with open(temp_file.name, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            if self.args.verbose:
                self.logger.debug(f"Downloaded attachment to: {temp_file.name}")
            if os.path.exists(temp_file.name):
                return temp_file.name
            else:
                if self.args.verbose:
                    self.logger.error(f"Downloaded file does not exist: {temp_file.name}")
                return None
        except requests.RequestException as e:
            if self.args.verbose:
                self.logger.error(f"Failed to download attachment {attachment['title']}: {e}")
            if os.path.exists(temp_file.name):
                os.remove(temp_file.name)
            return None

    def scan_text(self, text, content_type, metadata=None):
        """Scan text content with TruffleHog v3, excluding PagerDutyApiKey detector, and yield findings with context."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=self.temp_dir.name) as temp_file:
            temp_file.write(text)
            temp_file_path = temp_file.name
        if self.args.verbose:
            self.logger.debug(f"Created temporary file for scanning: {temp_file_path}")
        try:
            if not os.path.exists(temp_file_path):
                if self.args.verbose:
                    self.logger.error(f"Temporary file does not exist: {temp_file_path}")
                return
            if self.args.verbose:
                self.logger.debug(f"Scanning text file: {temp_file_path}")
            result = subprocess.run(
                [self.trufflehog_path, "filesystem", temp_file_path, "--json", "--exclude-detectors", "PagerDutyApiKey"],
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout:
                findings = [json.loads(line) for line in result.stdout.strip().splitlines()]
                for finding in findings:
                    finding["content_type"] = content_type
                    finding["snippet"] = get_text_snippet(text, finding["Raw"])
                    if metadata:
                        finding.update(metadata)
                    yield finding
        except subprocess.CalledProcessError as e:
            if self.args.verbose:
                self.logger.error(f"TruffleHog scan failed for text content: {e}")
        finally:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

    def scan_batch(self, file_paths, content_type, metadata=None):
        """Scan multiple files with TruffleHog in a single command, excluding PagerDutyApiKey detector, silently skipping if no paths exist."""
        if not file_paths:
            return  # Silently skip if no file paths provided, no warning
        valid_paths = [path for path in file_paths if os.path.exists(path)]
        if not valid_paths:
            return  # Silently skip if no valid paths after filtering, no warning
        if self.args.verbose:
            self.logger.debug(f"Scanning batch with paths: {valid_paths}")
        try:
            temp_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
            if self.args.verbose:
                self.logger.debug(f"Created temporary directory for batch scan: {temp_dir}")
            for i, path in enumerate(valid_paths):
                new_path = os.path.join(temp_dir, f"file_{i}")
                os.rename(path, new_path)
            result = subprocess.run(
                [self.trufflehog_path, "filesystem", temp_dir, "--json", "--exclude-detectors", "PagerDutyApiKey"],
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout:
                findings = [json.loads(line) for line in result.stdout.strip().splitlines()]
                for finding in findings:
                    finding["content_type"] = content_type
                    # For batch scans (e.g., attachments), we don't have direct access to the text content here
                    finding["snippet"] = "N/A"  # Snippets are not available for batch scans
                    if metadata:
                        finding.update(metadata)
                    yield finding
        except subprocess.CalledProcessError as e:
            if self.args.verbose:
                self.logger.error(f"TruffleHog batch scan failed: {e}")
        finally:
            for file in os.listdir(temp_dir):
                file_path = os.path.join(temp_dir, file)
                if os.path.exists(file_path):
                    os.remove(file_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)

    def scan_file(self, file_path, content_type, metadata=None):
        """Scan a file with TruffleHog v3, excluding PagerDutyApiKey detector."""
        if not os.path.exists(file_path):
            if self.args.verbose:
                self.logger.error(f"File does not exist: {file_path}")
            return
        yield from self.scan_batch([file_path], content_type, metadata)

    def get_content_url(self, content):
        """Get the full URL of a content item (page or blog post)."""
        relative_url = content["_links"]["webui"]
        return f"{self.base_url}{relative_url}"

    def process_content(self, content, space_key):
        """Process a content item, scanning its versions, comments, and attachments thoroughly."""
        content_id = content["id"]
        content_type = content["type"]
        title = content["title"]
        base_url = self.get_content_url(content)

        # Track findings to avoid duplicates
        seen_findings = set()

        # Track the latest version of each attachment
        attachment_versions = {}

        # Create a unique temporary directory for this content item
        content_temp_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        if self.args.verbose:
            self.logger.debug(f"Created temporary directory for {content_id}: {content_temp_dir}")

        try:
            # Scan all versions
            current_version = content["version"]["number"]
            if self.args.verbose:
                self.logger.debug(f"Scanning {content_type} {title} with {current_version} versions")
            version_texts = []
            for version in range(1, current_version + 1):
                version_content = self.get_version_content(content_id, version)
                if version_content:
                    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, dir=content_temp_dir)
                    temp_file.write(version_content)
                    temp_file.close()
                    if os.path.exists(temp_file.name):
                        version_texts.append(temp_file.name)
                    if self.args.verbose:
                        self.logger.debug(f"Added version {version} file: {temp_file.name}")
                if self.args.verbose:
                    self.logger.debug(f"Scanning {len(version_texts)} version files with paths: {version_texts}")
                for finding in self.scan_text(
                    version_content,
                    content_type="page",
                    metadata={
                        "space_key": space_key,
                        "content_id": content_id,
                        "version": version,
                        "title": title,
                        "url": base_url,
                        "location": f"page content (version {version})"
                    }
                ):
                    self._output_finding(finding)

            # Batch comments
            comment_paths = []
            comments = self.get_comments(content_id)
            if self.args.verbose:
                self.logger.debug(f"Found {len(comments)} comments for content {content_id}")
            for comment in comments:
                try:
                    comment_body = comment["body"]["storage"]["value"]
                    comment_id = comment["id"]
                    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, dir=content_temp_dir)
                    temp_file.write(comment_body)
                    temp_file.close()
                    if os.path.exists(temp_file.name):
                        comment_paths.append(temp_file.name)
                    if self.args.verbose:
                        self.logger.debug(f"Added comment file: {temp_file.name}")
                    for finding in self.scan_text(
                        comment_body,
                        content_type="comment",
                        metadata={
                            "space_key": space_key,
                            "content_id": comment_id,
                            "parent_content_id": content_id,
                            "title": f"Comment on {title}",
                            "url": base_url,
                            "location": f"comment (ID: {comment_id})"
                        }
                    ):
                        self._output_finding(finding)
                except KeyError as e:
                    if self.args.verbose:
                        self.logger.warning(f"Skipping comment {comment.get('id', 'unknown')} due to missing key: {e}")
                    continue

            # Batch attachments with deduplication and unchanged version skipping
            attachment_paths = []
            attachments = self.get_attachments(content_id)
            if self.args.verbose:
                self.logger.debug(f"Found {len(attachments)} attachments for content {content_id}")
            for attachment in attachments:
                attachment_id = attachment["id"]
                attachment_title = attachment["title"]
                current_version = attachment["version"]["number"]
                if attachment_id in attachment_versions:
                    if attachment_versions[attachment_id] == current_version:
                        if self.args.verbose:
                            self.logger.debug(f"Skipping unchanged attachment {attachment_id} (version {current_version})")
                        continue
                attachment_versions[attachment_id] = current_version
                file_path = self.download_attachment(attachment)
                if file_path and os.path.exists(file_path):
                    attachment_paths.append(file_path)
                if self.args.verbose and file_path:
                    self.logger.debug(f"Added attachment file: {file_path}")
                elif file_path:
                    if self.args.verbose:
                        self.logger.error(f"Attachment file not found: {file_path}")
            if self.args.verbose:
                self.logger.debug(f"Scanning {len(attachment_paths)} attachment files with paths: {attachment_paths}")
            for finding in self.scan_batch(
                attachment_paths,
                content_type="attachment",
                metadata={
                    "space_key": space_key,
                    "attachment_id": attachment_id,
                    "title": attachment_title,
                    "url": base_url,
                    "location": f"attachment '{attachment_title}' (ID: {attachment_id})"
                }
            ):
                # Create a unique key for deduplication: attachment ID + raw finding
                finding_key = (attachment_id, finding["Raw"])
                if finding_key in seen_findings:
                    if self.args.verbose:
                        self.logger.debug(f"Skipping duplicate finding for attachment {attachment_id}: {finding['Raw']}")
                    continue
                seen_findings.add(finding_key)
                self._output_finding(finding)
        except Exception as e:
            if self.args.verbose:
                self.logger.error(f"Error processing content {content_id}: {e}")
        finally:
            # Clean up only this content's temporary files
            for path in version_texts + comment_paths + attachment_paths:
                if os.path.exists(path):
                    os.remove(path)
            if os.path.exists(content_temp_dir):
                os.rmdir(content_temp_dir)

    def _output_finding(self, finding):
        """Output a finding to the console or file, ensuring only identified issues are shown by default."""
        version_info = f" (version {finding.get('version', 'N/A')})" if 'version' in finding else ""
        log_message = (
            f"Found {finding['DetectorName']}: {finding['Raw']} (Verified: {finding['Verified']}) "
            f"in {finding['content_type']} '{finding['title']}'{version_info} at {finding['url']} "
            f"[Location: {finding['location']}, Snippet: {finding['snippet']}]"
        )
        if self.output_file:
            self.output_file.write(json.dumps(finding) + "\n")
        else:
            self.logger.info(log_message)

    def scan_space_parallel(self, space):
        """Scan a single Confluence space for secrets in parallel, ensuring thorough coverage."""
        space_key = space["key"]
        if self.args.verbose:
            self.logger.info(f"Scanning space: {space_key}")

        # Scan space description (sequential for simplicity)
        description = space.get("description", {}).get("plain", {}).get("value", "")
        if description:
            if self.args.verbose:
                self.logger.debug(f"Scanning space description for space {space_key}")
            for finding in self.scan_text(
                description,
                content_type="space_description",
                metadata={
                    "space_key": space_key,
                    "title": f"Description of space {space_key}",
                    "url": f"{self.base_url}/spaces/{space_key}",
                    "location": "space description"
                }
            ):
                self._output_finding(finding)

        # Parallel scan for pages, blog posts, and ensure all content types are checked
        content_types = ["page", "blogpost"]  # Ensure all relevant content types are scanned
        with ThreadPoolExecutor(max_workers=2) as executor:  # Reduced from 5 to minimize race conditions
            futures = [
                executor.submit(self.process_content, content, space_key)
                for content_type in content_types
                for content in self.get_content_in_space(space_key, content_type)
            ]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    if self.args.verbose:
                        self.logger.error(f"Error in parallel scan: {e}")

    def run(self):
        """Run the secret scan across all or specified spaces, ensuring thorough scanning."""
        if self.args.space_keys:
            spaces_to_scan = []
            for key in self.args.space_keys:
                space = self.get_space_by_key(key)
                if space:
                    spaces_to_scan.append(space)
                else:
                    if self.args.verbose:
                        self.logger.error(f"Space with key '{key}' not found or inaccessible.")
            if not spaces_to_scan:
                if self.args.verbose:
                    self.logger.error("No valid spaces to scan. Exiting.")
                return
        else:
            spaces_to_scan = self.get_spaces()

        for space in spaces_to_scan:
            self.scan_space_parallel(space)

        if self.args.verbose:
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging for troubleshooting")

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