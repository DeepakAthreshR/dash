import git
import os
import logging

logger = logging.getLogger(__name__)

class GitHubHandler:
    def clone_repo(self, repo_url, dest_path, branch='main', token=None):
        """Clone a GitHub repository to a temporary directory - original repo is never modified"""
        try:
            # Ensure destination doesn't exist
            if os.path.exists(dest_path):
                import shutil
                shutil.rmtree(dest_path)
                logger.info(f"🧹 Removed existing directory: {dest_path}")

            # Create parent directory
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            try:
                os.chmod(os.path.dirname(dest_path), 0o777)
            except:
                pass

            # Prepare authenticated URL if token provided
            clone_url = repo_url
            if token:
                # Convert HTTPS URL to authenticated format
                if clone_url.startswith('https://'):
                    # Remove any existing authentication
                    if '@' in clone_url:
                        # Extract just the repo part after @
                        parts = clone_url.split('@')
                        if len(parts) > 1:
                            clone_url = 'https://' + parts[-1]
                    # Insert token into URL
                    clone_url = clone_url.replace('https://', f'https://{token}@')
                    logger.info(f"🔐 Using authenticated URL for private repo")
                elif clone_url.startswith('git@'):
                    # For SSH, we'd need SSH keys, but for now use HTTPS with token
                    clone_url = repo_url.replace('git@github.com:', 'https://github.com/').replace('.git', '')
                    clone_url = clone_url.replace('https://', f'https://{token}@')
                    logger.info(f"🔐 Converted SSH to HTTPS with authentication")
            else:
                # Check if this might be a private repo (no public access)
                logger.warning(f"⚠️ No token provided - private repos may fail to clone")

            # Try cloning with specified branch
            try:
                logger.info(f"📥 Cloning {repo_url} (branch: {branch}) to temporary directory...")
                git.Repo.clone_from(
                    clone_url,
                    dest_path,
                    branch=branch,
                    depth=1
                )
                logger.info(f"✅ Repository cloned successfully to {dest_path}")
                
            except git.GitCommandError as e:
                # Try alternative branch
                alt_branch = 'master' if branch == 'main' else 'main'
                logger.warning(f"⚠️ Branch '{branch}' not found, trying '{alt_branch}'...")
                
                try:
                    git.Repo.clone_from(
                        clone_url,
                        dest_path,
                        branch=alt_branch,
                        depth=1
                    )
                    logger.info(f"✅ Repository cloned with branch '{alt_branch}'")
                except git.GitCommandError as e2:
                    logger.error(f"❌ Failed to clone repository: {str(e2)}")
                    raise Exception(f"Failed to clone repository. Branch '{branch}' and '{alt_branch}' not found. Error: {str(e2)}")

            # Set permissions
            try:
                os.chmod(dest_path, 0o777)
            except:
                pass
            
            logger.info(f"✅ Cloned repository to temporary directory - original repo unchanged")
            
        except Exception as e:
            logger.error(f"❌ Clone error: {str(e)}")
            raise
