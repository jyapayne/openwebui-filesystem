"""
title: File System
author: Jojomaw
author_url: https://github.com/jojomaw
git_url: https://github.com/jojomaw/filesystem.git 
description: This tool provides a comprehensive set of file system operations, including file and directory management, search, and analysis.
required_open_webui_version: 0.1.0
requirements:
version: 0.1.0
licence: MIT
"""
import os
import json
import shutil
import logging
import hashlib
import datetime
import zipfile
import tarfile
import stat as pystat
import tempfile
import mimetypes
import base64
import asyncio
import aiofiles
import aiofiles.os
import aiohttp
from collections import defaultdict
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional, Union

# Use module logger instead of global basicConfig
logger = logging.getLogger(__name__)


class Tools:
    class Valves(BaseModel):
        root_restriction_directory: str = Field(
            default=os.getcwd(),
            description="Which folder the filesystem tool can access",
        )
        verbose_logging: bool = Field(
            default=False,
            description="Enable verbose logging for filesystem operations",
        )
        max_search_file_size: int = Field(
            default=10 * 1024 * 1024,  # 10MB
            description="Maximum file size to search through (bytes)",
        )
        return_relative_paths: bool = Field(
            default=True,
            description="Return paths relative to restriction root instead of absolute paths",
        )
        openrouter_api_key: str = Field(
            default="",
            description="OpenRouter API key for file uploads to models",
        )
        openrouter_model: str = Field(
            default="google/gemini-2.5-flash",
            description="Default OpenRouter model for file processing",
        )
        openrouter_base_url: str = Field(
            default="https://openrouter.ai/api/v1",
            description="OpenRouter API base URL",
        )
        spoof_directory_root: str = Field(
            default="",
            description="Display directory root for results (defaults to root_restriction_directory if empty)",
        )
        debug: bool = Field(
            default=False,
            description="Enable debug mode to show internal information like actual paths and spoofing details",
        )

    def __init__(self, base_path: Optional[str] = None):
        self.valves = self.Valves()
        # Use base_path as restriction root if provided, otherwise use valves default
        if base_path:
            self.valves.root_restriction_directory = base_path
        self.tags = defaultdict(list)  # Will be keyed by resolved path
        self.versions = defaultdict(list)  # Will be keyed by resolved path
        
        # Configure logging level based on valves
        if self.valves.verbose_logging:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

    def _result(self, ok: bool, action: str = "", subject_type: str = "", **kwargs) -> Dict[str, Any]:
        """Helper function to create consistent result format."""
        result = {"ok": ok, "action": action, "subject_type": subject_type}
        result.update(kwargs)
        
        # Add debug information if debug mode is enabled
        if self.valves.debug:
            actual_root = Path(self.valves.root_restriction_directory).resolve()
            display_root = self.valves.spoof_directory_root if self.valves.spoof_directory_root else self.valves.root_restriction_directory
            
            result.update({
                "debug_info": {
                    "actual_path": str(actual_root),
                    "display_path": display_root,
                    "is_spoofed": display_root != str(actual_root),
                    "spoof_directory_root": self.valves.spoof_directory_root,
                    "root_restriction_directory": self.valves.root_restriction_directory
                }
            })
        
        return result

    def _resolve_under_restriction(self, path: str) -> str:
        """Resolve path safely under the restriction root to prevent traversal outside."""
        base = Path(self.valves.root_restriction_directory).resolve()
        p = (base / path).resolve()
        if not str(p).startswith(str(base)):
            raise ValueError(f"Path escapes restriction root: {path}")
        return str(p)

    def _get_relative_path(self, absolute_path: str) -> str:
        """Convert absolute path to relative path from display root (spoof directory)."""
        if not self.valves.return_relative_paths:
            return absolute_path
        try:
            # Use spoof directory root for display if set, otherwise use restriction root
            display_root = self.valves.spoof_directory_root if self.valves.spoof_directory_root else self.valves.root_restriction_directory
            base = Path(self.valves.root_restriction_directory).resolve()
            spoof_base = Path(display_root).resolve()
            
            # Get relative path from actual restriction root
            relative_from_actual = str(Path(absolute_path).relative_to(base))
            
            # If spoof directory is same as restriction directory, return as-is
            if str(spoof_base) == str(base):
                return relative_from_actual
            
            # Otherwise, prepend the spoof directory to the relative path
            return str(Path(display_root) / relative_from_actual)
        except ValueError:
            # If path is not under base, return as-is
            return absolute_path

    async def _ensure_parent_dir(self, file_path: str) -> None:
        """Ensure parent directory exists for the given file path."""
        parent_dir = os.path.dirname(file_path)
        if parent_dir:
            await aiofiles.os.makedirs(parent_dir, exist_ok=True)

    async def _atomic_write(self, file_path: str, content: str, encoding: str = "utf-8") -> None:
        """Write content to file atomically using temporary file."""
        await self._ensure_parent_dir(file_path)
        temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(file_path), text=True)
        try:
            # Close the file descriptor immediately since we'll use aiofiles to write
            os.close(temp_fd)
            async with aiofiles.open(temp_path, 'w', encoding=encoding) as temp_file:
                await temp_file.write(content)
            await aiofiles.os.replace(temp_path, file_path)
        except Exception:
            # Clean up temp file if something went wrong
            try:
                await aiofiles.os.unlink(temp_path)
            except OSError:
                pass
            raise

    async def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is likely binary by examining first chunk."""
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                chunk = await f.read(1024)
                return b'\0' in chunk
        except Exception:
            return True  # Assume binary if can't read

    def _sanitize_archive_path(self, member_path: str, output_dir: str) -> str:
        """Sanitize archive member path to prevent directory traversal."""
        # Remove leading slashes and resolve any .. components
        clean_path = os.path.normpath(member_path.lstrip('/'))
        if clean_path.startswith('..') or os.path.isabs(clean_path):
            raise ValueError(f"Unsafe archive member path: {member_path}")
        
        # Ensure the final path is under output directory
        final_path = os.path.join(output_dir, clean_path)
        if not os.path.abspath(final_path).startswith(os.path.abspath(output_dir)):
            raise ValueError(f"Archive member would extract outside target directory: {member_path}")
        
        return final_path

    async def cwd(self) -> Dict[str, Any]:
        """
        Get the current working directory (returns the spoofed directory root for display).
        :return: The current working directory path as it should be displayed to users.
        """
        try:
            # Use spoof directory root for display if set, otherwise use restriction root
            display_root = self.valves.spoof_directory_root if self.valves.spoof_directory_root else self.valves.root_restriction_directory
            
            # Ensure the display root path exists (for validation)
            actual_root = Path(self.valves.root_restriction_directory).resolve()
            if not await aiofiles.os.path.exists(str(actual_root)):
                return self._result(
                    False,
                    action="cwd",
                    subject_type="directory",
                    error="Current working directory does not exist",
                    path=display_root
                )
            
            # Return the spoofed directory as the current working directory
            logger.info(f"Current working directory: {display_root}")
            
            return self._result(
                True,
                action="cwd",
                subject_type="directory",
                path=display_root
            )
        except Exception as e:
            return self._result(
                False,
                action="cwd",
                subject_type="directory",
                error=f"Failed to get current working directory: {str(e)}"
            )

    async def create_folder(self, folder_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new folder.
        :param folder_name: The name of the folder to create.
        :param base_dir: The base directory where the folder should be created.
        :return: A success message if the folder is created successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            folder_path = self._resolve_under_restriction(os.path.join(base_path, folder_name))
            
            if not await aiofiles.os.path.exists(folder_path):
                await aiofiles.os.makedirs(folder_path)
                logger.info(f"Folder '{folder_name}' created successfully at {folder_path}")
                return self._result(
                    True,
                    action="create",
                    subject_type="folder",
                    message=f"Folder '{folder_name}' created successfully",
                    path=self._get_relative_path(folder_path)
                )
            else:
                logger.warning(f"Folder '{folder_name}' already exists at {folder_path}")
                return self._result(
                    True,
                    action="create",
                    subject_type="folder",
                    message=f"Folder '{folder_name}' already exists",
                    path=self._get_relative_path(folder_path)
                )
        except ValueError as e:
            return self._result(False, action="create", subject_type="folder", error=str(e))
        except OSError as e:
            return self._result(False, action="create", subject_type="folder", error=f"Failed to create folder: {str(e)}")

    async def delete_folder(self, folder_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a folder.
        :param folder_name: The name of the folder to delete.
        :param base_dir: The base directory where the folder is located.
        :return: A success message if the folder is deleted successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            folder_path = self._resolve_under_restriction(os.path.join(base_path, folder_name))
            
            if await aiofiles.os.path.exists(folder_path):
                if not await aiofiles.os.path.isdir(folder_path):
                    return self._result(False, action="delete", subject_type="folder", error="Path is not a directory")
                
                await asyncio.to_thread(shutil.rmtree, folder_path)
                logger.info(f"Folder '{folder_name}' deleted successfully from {folder_path}")
                return self._result(
                    True,
                    action="delete",
                    subject_type="folder",
                    message=f"Folder '{folder_name}' deleted successfully",
                    path=self._get_relative_path(folder_path)
                )
            else:
                return self._result(
                    False,
                    action="delete",
                    subject_type="folder",
                    error="Folder does not exist",
                    path=self._get_relative_path(folder_path)
                )
        except ValueError as e:
            return self._result(False, action="delete", subject_type="folder", error=str(e))
        except OSError as e:
            return self._result(False, action="delete", subject_type="folder", error=f"Failed to delete folder: {str(e)}")

    async def create_file(self, file_name: str, content: str = "", base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new file.
        :param file_name: The name of the file to create.
        :param content: The content to write to the file.
        :param base_dir: The base directory where the file should be created.
        :return: A success message if the file is created successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            await self._atomic_write(file_path, content)
            logger.info(f"File '{file_name}' created successfully at {file_path}")
            return self._result(
                True,
                action="create",
                subject_type="file",
                message=f"File '{file_name}' created successfully",
                path=self._get_relative_path(file_path),
                bytes=len(content.encode('utf-8'))
            )
        except ValueError as e:
            return self._result(False, action="create", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="create", subject_type="file", error=f"Failed to create file: {str(e)}")

    async def delete_file(self, file_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Delete a file.
        :param file_name: The name of the file to delete.
        :param base_dir: The base directory where the file is located.
        :return: A success message if the file is deleted successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="delete",
                    subject_type="file",
                    error="File does not exist",
                    path=self._get_relative_path(file_path)
                )
            
            if await aiofiles.os.path.isdir(file_path):
                return self._result(False, action="delete", subject_type="file", error="Path is a directory")
            
            await aiofiles.os.remove(file_path)
            logger.info(f"File '{file_name}' deleted successfully from {file_path}")
            return self._result(
                True,
                action="delete",
                subject_type="file",
                message=f"File '{file_name}' deleted successfully",
                path=self._get_relative_path(file_path)
            )
        except ValueError as e:
            return self._result(False, action="delete", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="delete", subject_type="file", error=f"Failed to delete file: {str(e)}")

    async def read_file(
        self,
        file_name: str,
        base_dir: Optional[str] = None,
        auto_transcribe_binary: bool = True,
        auto_describe_images: bool = True,
        image_description_type: str = "brief",
        force_binary: bool = False
    ) -> Dict[str, Any]:
        """
        Read the content of a file. Automatically transcribes binary files (images, PDFs) to text.
        For images, can provide AI-generated descriptions instead of base64 content.
        :param file_name: The name of the file to read.
        :param base_dir: The base directory where the file is located.
        :param auto_transcribe_binary: Whether to automatically transcribe binary files to text.
        :param auto_describe_images: Whether to automatically describe image files using AI.
        :param image_description_type: Type of image description ('detailed', 'brief', 'technical', 'creative').
        :param force_binary: If True, always return binary files as base64, bypassing AI processing.
        :return: The content of the file (text for text files, descriptions/transcribed text for binary files).
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="read",
                    subject_type="file",
                    error="File not found",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(False, action="read", subject_type="file", error="Path is not a file")
            
            # Check if file is binary first
            is_binary = await self._is_binary_file(file_path) if (auto_transcribe_binary or auto_describe_images or force_binary) else False
            
            # If force_binary is True, skip all AI processing and return base64
            if force_binary and is_binary:
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type is None:
                    mime_type = "application/octet-stream"
                
                async with aiofiles.open(file_path, "rb") as file:
                    binary_content = await file.read()
                
                base64_content = base64.b64encode(binary_content).decode('utf-8')
                
                logger.info(f"Binary file '{file_name}' returned as base64 (force_binary=True)")
                return self._result(
                    True,
                    action="read",
                    subject_type="file",
                    path=self._get_relative_path(file_path),
                    content=base64_content,
                    encoding="base64",
                    mime_type=mime_type,
                    is_binary=True,
                    force_binary=True,
                    bytes=len(binary_content)
                )
            
            if is_binary and (auto_transcribe_binary or auto_describe_images):
                # Get MIME type for processing decisions
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type is None:
                    mime_type = "application/octet-stream"
                
                # Check if it's an image and auto_describe_images is enabled
                if mime_type.startswith('image/') and auto_describe_images and self.valves.openrouter_api_key:
                    logger.info(f"Describing image file '{file_name}' ({mime_type})")
                    description_result = await self.describe_image(
                        file_name=file_name,
                        base_dir=base_dir,
                        description_type=image_description_type
                    )
                    
                    if description_result["ok"]:
                        description_text = description_result.get("description", "")
                        logger.info(f"Image file '{file_name}' successfully described")
                        return self._result(
                            True,
                            action="read",
                            subject_type="file",
                            path=self._get_relative_path(file_path),
                            content=description_text,
                            encoding="image_description",
                            mime_type=mime_type,
                            is_binary=True,
                            is_image=True,
                            description_attempted=True,
                            description_successful=True,
                            description_type=image_description_type,
                            model=description_result.get("model", ""),
                            word_count=description_result.get("word_count", 0),
                            character_count=description_result.get("character_count", 0),
                            bytes=description_result.get("file_size", 0)
                        )
                    else:
                        logger.warning(f"Image description failed for '{file_name}', falling back to base64")
                        # Fall through to base64 handling below
                
                # Handle transcription for non-images or when image description is disabled/failed
                if auto_transcribe_binary:
                    # Check if we have OpenRouter API key for transcription
                    if not self.valves.openrouter_api_key:
                        # Fallback to base64 if no API key
                        async with aiofiles.open(file_path, "rb") as file:
                            binary_content = await file.read()
                        
                        base64_content = base64.b64encode(binary_content).decode('utf-8')
                        
                        logger.warning(f"Binary file '{file_name}' returned as base64 - no OpenRouter API key for transcription")
                        return self._result(
                            True,
                            action="read",
                            subject_type="file",
                            path=self._get_relative_path(file_path),
                            content=base64_content,
                            encoding="base64",
                            mime_type=mime_type,
                            is_binary=True,
                            transcription_attempted=False,
                            note="Returned as base64 - set openrouter_api_key for automatic transcription",
                            bytes=len(binary_content)
                        )
                    
                    # Check if file type is supported for transcription
                    if mime_type and self._is_file_supported_by_openrouter(mime_type):
                        # Transcribe the binary file
                        logger.info(f"Transcribing binary file '{file_name}' ({mime_type})")
                        transcription_result = await self.transcribe_file(
                            file_name=file_name,
                            base_dir=base_dir,
                            transcription_mode="auto",
                            output_format="text"
                        )
                        
                        if transcription_result["ok"]:
                            transcribed_text = transcription_result.get("transcribed_text", "")
                            logger.info(f"Binary file '{file_name}' successfully transcribed to text")
                            return self._result(
                                True,
                                action="read",
                                subject_type="file",
                                path=self._get_relative_path(file_path),
                                content=transcribed_text,
                                encoding="transcribed_text",
                                mime_type=mime_type,
                                is_binary=True,
                                transcription_attempted=True,
                                transcription_successful=True,
                                transcription_mode=transcription_result.get("transcription_mode", "auto"),
                                model=transcription_result.get("model", ""),
                                word_count=transcription_result.get("word_count", 0),
                                character_count=transcription_result.get("character_count", 0),
                                bytes=transcription_result.get("file_size", 0)
                            )
                        else:
                            # Transcription failed, fallback to base64
                            logger.warning(f"Transcription failed for '{file_name}', falling back to base64")
                            async with aiofiles.open(file_path, "rb") as file:
                                binary_content = await file.read()
                            
                            base64_content = base64.b64encode(binary_content).decode('utf-8')
                            return self._result(
                                True,
                                action="read",
                                subject_type="file",
                                path=self._get_relative_path(file_path),
                                content=base64_content,
                                encoding="base64",
                                mime_type=mime_type,
                                is_binary=True,
                                transcription_attempted=True,
                                transcription_successful=False,
                                transcription_error=transcription_result.get("error", "Unknown error"),
                                bytes=len(binary_content)
                            )
                    else:
                        # Unsupported file type for transcription, return base64
                        async with aiofiles.open(file_path, "rb") as file:
                            binary_content = await file.read()
                        
                        base64_content = base64.b64encode(binary_content).decode('utf-8')
                        logger.info(f"Binary file '{file_name}' returned as base64 - unsupported type for transcription")
                        return self._result(
                            True,
                            action="read",
                            subject_type="file",
                            path=self._get_relative_path(file_path),
                            content=base64_content,
                            encoding="base64",
                            mime_type=mime_type or "application/octet-stream",
                            is_binary=True,
                            transcription_attempted=False,
                            note="File type not supported for transcription",
                            bytes=len(binary_content)
                        )
                else:
                    # Neither transcription nor description enabled/available, return base64
                    async with aiofiles.open(file_path, "rb") as file:
                        binary_content = await file.read()
                    
                    base64_content = base64.b64encode(binary_content).decode('utf-8')
                    return self._result(
                        True,
                        action="read",
                        subject_type="file",
                        path=self._get_relative_path(file_path),
                        content=base64_content,
                        encoding="base64",
                        mime_type=mime_type,
                        is_binary=True,
                        bytes=len(binary_content)
                    )
            else:
                # Handle as text file, but check if force_binary is requested
                if force_binary:
                    # Force binary mode even for text files
                    mime_type, _ = mimetypes.guess_type(file_path)
                    if mime_type is None:
                        mime_type = "text/plain"
                    
                    async with aiofiles.open(file_path, "rb") as file:
                        binary_content = await file.read()
                    
                    base64_content = base64.b64encode(binary_content).decode('utf-8')
                    
                    logger.info(f"Text file '{file_name}' returned as base64 (force_binary=True)")
                    return self._result(
                        True,
                        action="read",
                        subject_type="file",
                        path=self._get_relative_path(file_path),
                        content=base64_content,
                        encoding="base64",
                        mime_type=mime_type,
                        is_binary=False,
                        force_binary=True,
                        bytes=len(binary_content)
                    )
                else:
                    # Normal text file handling
                    async with aiofiles.open(file_path, "r", encoding="utf-8") as file:
                        content = await file.read()
                    
                    logger.info(f"Text file '{file_name}' read successfully from {file_path}")
                    return self._result(
                        True,
                        action="read",
                        subject_type="file",
                        path=self._get_relative_path(file_path),
                        content=content,
                        encoding="utf-8",
                        is_binary=False,
                        bytes=len(content.encode('utf-8'))
                    )
                
        except UnicodeDecodeError as e:
            # Fallback: if UTF-8 decoding fails, treat as binary
            if auto_transcribe_binary:
                logger.warning(f"UTF-8 decode failed for '{file_name}', treating as binary file")
                try:
                    # Re-resolve file path for fallback (should be same as above)
                    base_path = base_dir if base_dir else "."
                    fallback_file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
                    
                    # Try transcription first if API key is available
                    if self.valves.openrouter_api_key:
                        mime_type, _ = mimetypes.guess_type(fallback_file_path)
                        if mime_type and self._is_file_supported_by_openrouter(mime_type):
                            transcription_result = await self.transcribe_file(
                                file_name=file_name,
                                base_dir=base_dir,
                                transcription_mode="auto",
                                output_format="text"
                            )
                            
                            if transcription_result["ok"]:
                                transcribed_text = transcription_result.get("transcribed_text", "")
                                return self._result(
                                    True,
                                    action="read",
                                    subject_type="file",
                                    path=self._get_relative_path(fallback_file_path),
                                    content=transcribed_text,
                                    encoding="transcribed_text",
                                    mime_type=mime_type,
                                    is_binary=True,
                                    transcription_attempted=True,
                                    transcription_successful=True,
                                    note="Transcribed due to UTF-8 decode error",
                                    bytes=transcription_result.get("file_size", 0)
                                )
                    
                    # Fallback to base64 if transcription not available or failed
                    mime_type, _ = mimetypes.guess_type(fallback_file_path)
                    if mime_type is None:
                        mime_type = "application/octet-stream"
                    
                    async with aiofiles.open(fallback_file_path, "rb") as file:
                        binary_content = await file.read()
                    
                    base64_content = base64.b64encode(binary_content).decode('utf-8')
                    
                    return self._result(
                        True,
                        action="read",
                        subject_type="file",
                        path=self._get_relative_path(fallback_file_path),
                        content=base64_content,
                        encoding="base64",
                        mime_type=mime_type,
                        is_binary=True,
                        bytes=len(binary_content),
                        note="Treated as binary due to encoding error"
                    )
                except Exception as fallback_error:
                    return self._result(False, action="read", subject_type="file",
                                      error=f"Failed to read as binary fallback: {str(fallback_error)}")
            else:
                return self._result(False, action="read", subject_type="file", error=f"File encoding error: {str(e)}")
        except ValueError as e:
            return self._result(False, action="read", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="read", subject_type="file", error=f"Failed to read file: {str(e)}")

    async def get_file_info_extended(self, file_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Get extended metadata and information about a file, including MIME type and binary detection.
        :param file_name: The name of the file to analyze.
        :param base_dir: The base directory where the file is located.
        :return: Extended file information including MIME type, binary status, etc.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="file_info_extended",
                    subject_type="file",
                    error="File does not exist",
                    path=self._get_relative_path(file_path)
                )
            
            # Get basic file stats
            st = await aiofiles.os.stat(file_path)
            
            # Get MIME type
            mime_type, encoding = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = "application/octet-stream"
            
            # Check if file is binary
            is_binary = await self._is_binary_file(file_path) if await aiofiles.os.path.isfile(file_path) else False
            
            # Calculate file hash for integrity checking
            file_hash = None
            if await aiofiles.os.path.isfile(file_path) and st.st_size < 100 * 1024 * 1024:  # Only hash files < 100MB
                try:
                    async with aiofiles.open(file_path, 'rb') as f:
                        content = await f.read()
                        file_hash = hashlib.sha256(content).hexdigest()
                except Exception:
                    pass  # Skip hash if can't read file
            
            return self._result(
                True,
                action="file_info_extended",
                subject_type="file",
                path=self._get_relative_path(file_path),
                name=os.path.basename(file_path),
                is_dir=await aiofiles.os.path.isdir(file_path),
                is_file=await aiofiles.os.path.isfile(file_path),
                is_symlink=await aiofiles.os.path.islink(file_path),
                is_binary=is_binary,
                size=st.st_size,
                mime_type=mime_type,
                encoding=encoding,
                mode=pystat.filemode(st.st_mode),
                mtime=st.st_mtime,
                ctime=st.st_ctime,
                atime=st.st_atime,
                created=datetime.datetime.utcfromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                modified=datetime.datetime.utcfromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                accessed=datetime.datetime.utcfromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                hash_sha256=file_hash
            )
        except ValueError as e:
            return self._result(False, action="file_info_extended", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="file_info_extended", subject_type="file", error=f"Failed to get file info: {str(e)}")

    async def write_to_file(self, file_name: str, content: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Write content to a file.
        :param file_name: The name of the file to write to.
        :param content: The content to write to the file.
        :param base_dir: The base directory where the file is located.
        :return: A success message if the content is written successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            await self._atomic_write(file_path, content)
            logger.info(f"Content written to file '{file_name}' successfully at {file_path}")
            return self._result(
                True,
                action="write",
                subject_type="file",
                path=self._get_relative_path(file_path),
                bytes=len(content.encode('utf-8'))
            )
        except ValueError as e:
            return self._result(False, action="write", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="write", subject_type="file", error=f"Failed to write file: {str(e)}")

    async def list_files(self, base_dir: Optional[str] = None, include_hidden: bool = False) -> Dict[str, Any]:
        """
        List all files in the specified directory.
        :param base_dir: The base directory where the files should be listed.
        :param include_hidden: Whether to include hidden files (starting with .).
        :return: A list of files in the specified directory.
        """
        try:
            base_path = base_dir if base_dir else "."
            directory_path = self._resolve_under_restriction(base_path)
            
            if not await aiofiles.os.path.exists(directory_path):
                return self._result(
                    False,
                    action="list",
                    subject_type="directory",
                    error="Path does not exist",
                    path=self._get_relative_path(directory_path)
                )
            
            if not await aiofiles.os.path.isdir(directory_path):
                return self._result(
                    False,
                    action="list",
                    subject_type="directory",
                    error="Path is not a directory",
                    path=self._get_relative_path(directory_path)
                )
            
            entries = []
            dir_entries = await aiofiles.os.listdir(directory_path)
            for entry in sorted(dir_entries, key=lambda x: x.lower()):
                if not include_hidden and entry.startswith('.'):
                    continue
                    
                entry_path = os.path.join(directory_path, entry)
                try:
                    st = await aiofiles.os.stat(entry_path)
                    is_dir = await aiofiles.os.path.isdir(entry_path)
                    entries.append({
                        "name": entry,
                        "path": self._get_relative_path(entry_path),
                        "type": "dir" if is_dir else "file",
                        "size": None if is_dir else st.st_size,
                        "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "permissions": pystat.filemode(st.st_mode),
                    })
                except Exception as e:
                    entries.append({
                        "name": entry,
                        "path": self._get_relative_path(entry_path),
                        "type": "unknown",
                        "error": str(e)
                    })
            
            logger.info(f"Files listed successfully from {directory_path}")
            return self._result(
                True,
                action="list",
                subject_type="directory",
                entries=entries,
                path=self._get_relative_path(directory_path),
                count=len(entries)
            )
        except ValueError as e:
            return self._result(False, action="list", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="list", subject_type="directory", error=f"Failed to list directory: {str(e)}")

    async def is_file(self, path: str) -> bool:
        """
        Check if the given path is a file.
        :param path: The path to check.
        :return: True if the path is a file, False otherwise.
        """
        try:
            resolved_path = self._resolve_under_restriction(path)
            return await aiofiles.os.path.isfile(resolved_path)
        except (ValueError, OSError):
            return False

    async def is_directory(self, path: str) -> bool:
        """
        Check if the given path is a directory.
        :param path: The path to check.
        :return: True if the path is a directory, False otherwise.
        """
        try:
            resolved_path = self._resolve_under_restriction(path)
            return await aiofiles.os.path.isdir(resolved_path)
        except (ValueError, OSError):
            return False

    async def get_file_metadata(self, file_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Get metadata of a file.
        :param file_name: The name of the file to get metadata for.
        :param base_dir: The base directory where the file is located.
        :return: A dictionary containing the file's metadata.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="metadata",
                    subject_type="file",
                    error="Path does not exist",
                    path=self._get_relative_path(file_path)
                )
            
            st = await aiofiles.os.stat(file_path)
            return self._result(
                True,
                action="metadata",
                subject_type="file",
                path=self._get_relative_path(file_path),
                is_dir=await aiofiles.os.path.isdir(file_path),
                is_file=await aiofiles.os.path.isfile(file_path),
                is_symlink=await aiofiles.os.path.islink(file_path),
                size=st.st_size,
                mode=pystat.filemode(st.st_mode),
                mtime=st.st_mtime,
                ctime=st.st_ctime,
                atime=st.st_atime,
                created=datetime.datetime.utcfromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                modified=datetime.datetime.utcfromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                accessed=datetime.datetime.utcfromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S UTC"),
            )
        except ValueError as e:
            return self._result(False, action="metadata", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="metadata", subject_type="file", error=f"Failed to get metadata: {str(e)}")

    async def copy_file(
        self, src_file: str, dest_file: str, src_base_dir: Optional[str] = None, dest_base_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Copy a file from source to destination.
        :param src_file: The name of the source file.
        :param dest_file: The name of the destination file.
        :param src_base_dir: The base directory where the source file is located.
        :param dest_base_dir: The base directory where the destination file should be created.
        :return: A success message if the file is copied successfully.
        """
        try:
            src_base = src_base_dir if src_base_dir else "."
            dest_base = dest_base_dir if dest_base_dir else "."
            src_file_path = self._resolve_under_restriction(os.path.join(src_base, src_file))
            dest_file_path = self._resolve_under_restriction(os.path.join(dest_base, dest_file))
            
            if not await aiofiles.os.path.exists(src_file_path):
                return self._result(
                    False,
                    action="copy",
                    subject_type="file",
                    error="Source file does not exist",
                    src=self._get_relative_path(src_file_path)
                )
            
            if not await aiofiles.os.path.isfile(src_file_path):
                return self._result(False, action="copy", subject_type="file", error="Source path is not a file")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(src_file_path):
                return self._result(False, action="copy", subject_type="file", error="Cannot copy symlinks")
            
            await self._ensure_parent_dir(dest_file_path)
            await asyncio.to_thread(shutil.copy2, src_file_path, dest_file_path)
            
            logger.info(f"File '{src_file}' copied successfully to {dest_file_path}")
            return self._result(
                True,
                action="copy",
                subject_type="file",
                src=self._get_relative_path(src_file_path),
                dst=self._get_relative_path(dest_file_path)
            )
        except ValueError as e:
            return self._result(False, action="copy", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="copy", subject_type="file", error=f"Failed to copy file: {str(e)}")

    async def copy_folder(
        self,
        src_folder: str,
        dest_folder: str,
        src_base_dir: Optional[str] = None,
        dest_base_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Copy a folder from source to destination.
        :param src_folder: The name of the source folder.
        :param dest_folder: The name of the destination folder.
        :param src_base_dir: The base directory where the source folder is located.
        :param dest_base_dir: The base directory where the destination folder should be created.
        :return: A success message if the folder is copied successfully.
        """
        try:
            src_base = src_base_dir if src_base_dir else "."
            dest_base = dest_base_dir if dest_base_dir else "."
            src_folder_path = self._resolve_under_restriction(os.path.join(src_base, src_folder))
            dest_folder_path = self._resolve_under_restriction(os.path.join(dest_base, dest_folder))
            
            if not await aiofiles.os.path.exists(src_folder_path):
                return self._result(
                    False,
                    action="copy",
                    subject_type="folder",
                    error="Source folder does not exist",
                    src=self._get_relative_path(src_folder_path)
                )
            
            if not await aiofiles.os.path.isdir(src_folder_path):
                return self._result(False, action="copy", subject_type="folder", error="Source path is not a directory")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(src_folder_path):
                return self._result(False, action="copy", subject_type="folder", error="Cannot copy symlinked directories")
            
            # Use dirs_exist_ok=True to handle existing destinations
            await asyncio.to_thread(shutil.copytree, src_folder_path, dest_folder_path, dirs_exist_ok=True, symlinks=False)
            
            logger.info(f"Folder '{src_folder}' copied successfully to {dest_folder_path}")
            return self._result(
                True,
                action="copy",
                subject_type="folder",
                src=self._get_relative_path(src_folder_path),
                dst=self._get_relative_path(dest_folder_path)
            )
        except ValueError as e:
            return self._result(False, action="copy", subject_type="folder", error=str(e))
        except OSError as e:
            return self._result(False, action="copy", subject_type="folder", error=f"Failed to copy folder: {str(e)}")

    async def move_file(
        self, src_file: str, dest_file: str, src_base_dir: Optional[str] = None, dest_base_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Move a file from source to destination.
        :param src_file: The name of the source file.
        :param dest_file: The name of the destination file.
        :param src_base_dir: The base directory where the source file is located.
        :param dest_base_dir: The base directory where the destination file should be created.
        :return: A success message if the file is moved successfully.
        """
        try:
            src_base = src_base_dir if src_base_dir else "."
            dest_base = dest_base_dir if dest_base_dir else "."
            src_file_path = self._resolve_under_restriction(os.path.join(src_base, src_file))
            dest_file_path = self._resolve_under_restriction(os.path.join(dest_base, dest_file))
            
            if not await aiofiles.os.path.exists(src_file_path):
                return self._result(
                    False,
                    action="move",
                    subject_type="file",
                    error="Source file does not exist",
                    src=self._get_relative_path(src_file_path)
                )
            
            if not await aiofiles.os.path.isfile(src_file_path):
                return self._result(False, action="move", subject_type="file", error="Source path is not a file")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(src_file_path):
                return self._result(False, action="move", subject_type="file", error="Cannot move symlinks")
            
            await self._ensure_parent_dir(dest_file_path)
            await asyncio.to_thread(shutil.move, src_file_path, dest_file_path)
            
            logger.info(f"File '{src_file}' moved successfully to {dest_file_path}")
            return self._result(
                True,
                action="move",
                subject_type="file",
                src=self._get_relative_path(src_file_path),
                dst=self._get_relative_path(dest_file_path)
            )
        except ValueError as e:
            return self._result(False, action="move", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="move", subject_type="file", error=f"Failed to move file: {str(e)}")

    async def move_folder(
        self,
        src_folder: str,
        dest_folder: str,
        src_base_dir: Optional[str] = None,
        dest_base_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Move a folder from source to destination.
        :param src_folder: The name of the source folder.
        :param dest_folder: The name of the destination folder.
        :param src_base_dir: The base directory where the source folder is located.
        :param dest_base_dir: The base directory where the destination folder should be created.
        :return: A success message if the folder is moved successfully.
        """
        try:
            src_base = src_base_dir if src_base_dir else "."
            dest_base = dest_base_dir if dest_base_dir else "."
            src_folder_path = self._resolve_under_restriction(os.path.join(src_base, src_folder))
            dest_folder_path = self._resolve_under_restriction(os.path.join(dest_base, dest_folder))
            
            if not await aiofiles.os.path.exists(src_folder_path):
                return self._result(
                    False,
                    action="move",
                    subject_type="folder",
                    error="Source folder does not exist",
                    src=self._get_relative_path(src_folder_path)
                )
            
            if not await aiofiles.os.path.isdir(src_folder_path):
                return self._result(False, action="move", subject_type="folder", error="Source path is not a directory")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(src_folder_path):
                return self._result(False, action="move", subject_type="folder", error="Cannot move symlinked directories")
            
            await self._ensure_parent_dir(dest_folder_path)
            await asyncio.to_thread(shutil.move, src_folder_path, dest_folder_path)
            
            logger.info(f"Folder '{src_folder}' moved successfully to {dest_folder_path}")
            return self._result(
                True,
                action="move",
                subject_type="folder",
                src=self._get_relative_path(src_folder_path),
                dst=self._get_relative_path(dest_folder_path)
            )
        except ValueError as e:
            return self._result(False, action="move", subject_type="folder", error=str(e))
        except OSError as e:
            return self._result(False, action="move", subject_type="folder", error=f"Failed to move folder: {str(e)}")

    async def batch_rename_files(
        self, directory: str, old_pattern: str, new_pattern: str
    ) -> Dict[str, Any]:
        """
        Batch rename files in a directory.
        :param directory: The directory containing the files to rename.
        :param old_pattern: The old pattern in the file names to replace.
        :param new_pattern: The new pattern to replace the old pattern with.
        :return: A success message if the files are renamed successfully.
        """
        try:
            directory_path = self._resolve_under_restriction(directory)
            
            if not await aiofiles.os.path.exists(directory_path):
                return self._result(
                    False,
                    action="batch_rename",
                    subject_type="directory",
                    error="Directory does not exist",
                    path=self._get_relative_path(directory_path)
                )
            
            if not await aiofiles.os.path.isdir(directory_path):
                return self._result(False, action="batch_rename", subject_type="directory", error="Path is not a directory")
            
            renamed = []
            failed = []
            
            dir_entries = await aiofiles.os.listdir(directory_path)
            for filename in dir_entries:
                if old_pattern in filename:
                    new_filename = filename.replace(old_pattern, new_pattern)
                    old_path = os.path.join(directory_path, filename)
                    new_path = os.path.join(directory_path, new_filename)
                    
                    # Skip symlinks for security
                    if await aiofiles.os.path.islink(old_path):
                        failed.append({"from": filename, "error": "Cannot rename symlinks"})
                        continue
                    
                    try:
                        await aiofiles.os.rename(old_path, new_path)
                        renamed.append({
                            "from": self._get_relative_path(old_path),
                            "to": self._get_relative_path(new_path)
                        })
                    except OSError as e:
                        failed.append({"from": filename, "error": str(e)})
            
            logger.info(f"Batch rename in directory '{directory}' completed: {len(renamed)} renamed, {len(failed)} failed")
            return self._result(
                True,
                action="batch_rename",
                subject_type="directory",
                message=f"Batch rename completed: {len(renamed)} renamed, {len(failed)} failed",
                renamed=renamed,
                failed=failed,
                path=self._get_relative_path(directory_path)
            )
        except ValueError as e:
            return self._result(False, action="batch_rename", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="batch_rename", subject_type="directory", error=f"Failed to access directory: {str(e)}")

    async def compress_file(
        self,
        file_name: str,
        output_filename: str,
        format: str = "zip",
        base_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compress a file into the specified format.
        :param file_name: The name of the file to compress.
        :param output_filename: The name of the output compressed file.
        :param format: The compression format ('zip', 'tar', 'gztar').
        :param base_dir: The base directory where the file is located.
        :return: A success message if the file is compressed successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            output_path = self._resolve_under_restriction(os.path.join(base_path, output_filename))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="compress",
                    subject_type="file",
                    error="Source file does not exist",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(False, action="compress", subject_type="file", error="Source path is not a file")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(file_path):
                return self._result(False, action="compress", subject_type="file", error="Cannot compress symlinks")
            
            await self._ensure_parent_dir(output_path)
            
            # Use asyncio.to_thread for CPU-bound compression operations
            if format == "zip":
                await asyncio.to_thread(self._compress_zip, file_path, output_path)
            elif format == "tar":
                await asyncio.to_thread(self._compress_tar, file_path, output_path)
            elif format == "gztar":
                await asyncio.to_thread(self._compress_gztar, file_path, output_path)
            else:
                return self._result(False, action="compress", subject_type="file", error=f"Unsupported compression format: {format}")
            
            logger.info(f"File '{file_name}' compressed successfully to {output_path}")
            return self._result(
                True,
                action="compress",
                subject_type="file",
                message="Compressed successfully",
                output=self._get_relative_path(output_path),
                format=format
            )
        except ValueError as e:
            return self._result(False, action="compress", subject_type="file", error=str(e))
        except (zipfile.BadZipFile, tarfile.TarError) as e:
            return self._result(False, action="compress", subject_type="file", error=f"Compression error: {str(e)}")
        except OSError as e:
            return self._result(False, action="compress", subject_type="file", error=f"Failed to compress file: {str(e)}")
    
    def _compress_zip(self, file_path: str, output_path: str) -> None:
        """Helper method for ZIP compression."""
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(file_path, os.path.basename(file_path))
    
    def _compress_tar(self, file_path: str, output_path: str) -> None:
        """Helper method for TAR compression."""
        with tarfile.open(output_path, "w") as tarf:
            tarf.add(file_path, os.path.basename(file_path))
    
    def _compress_gztar(self, file_path: str, output_path: str) -> None:
        """Helper method for GZTAR compression."""
        with tarfile.open(output_path, "w:gz") as tarf:
            tarf.add(file_path, os.path.basename(file_path))

    async def decompress_file(
        self, file_name: str, output_directory: str, base_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Decompress a file into the specified directory.
        :param file_name: The name of the file to decompress.
        :param output_directory: The directory where the decompressed files will be stored.
        :param base_dir: The base directory where the file is located.
        :return: A success message if the file is decompressed successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            output_path = self._resolve_under_restriction(os.path.join(base_path, output_directory))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="decompress",
                    subject_type="file",
                    error="Archive file does not exist",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(False, action="decompress", subject_type="file", error="Archive path is not a file")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(file_path):
                return self._result(False, action="decompress", subject_type="file", error="Cannot decompress symlinks")
            
            await self._ensure_parent_dir(output_path)
            await aiofiles.os.makedirs(output_path, exist_ok=True)
            
            # Use asyncio.to_thread for CPU-bound decompression operations
            extracted_files = await asyncio.to_thread(self._decompress_archive, file_path, output_path, file_name)
            
            logger.info(f"File '{file_name}' decompressed successfully to {output_path}")
            return self._result(
                True,
                action="decompress",
                subject_type="file",
                message="Decompressed successfully",
                output=self._get_relative_path(output_path),
                extracted_files=extracted_files,
                count=len(extracted_files)
            )
        except ValueError as e:
            return self._result(False, action="decompress", subject_type="file", error=str(e))
        except (zipfile.BadZipFile, tarfile.TarError) as e:
            return self._result(False, action="decompress", subject_type="file", error=f"Archive error: {str(e)}")
        except OSError as e:
            return self._result(False, action="decompress", subject_type="file", error=f"Failed to decompress file: {str(e)}")
    
    def _decompress_archive(self, file_path: str, output_path: str, file_name: str) -> List[str]:
        """Helper method for archive decompression."""
        extracted_files = []
        
        if file_name.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as zipf:
                for member in zipf.namelist():
                    # Sanitize each member path to prevent directory traversal
                    safe_path = self._sanitize_archive_path(member, output_path)
                    # Extract to the sanitized path
                    member_data = zipf.read(member)
                    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                    with open(safe_path, 'wb') as f:
                        f.write(member_data)
                    extracted_files.append(self._get_relative_path(safe_path))
        elif (
            file_name.endswith(".tar")
            or file_name.endswith(".tar.gz")
            or file_name.endswith(".tgz")
        ):
            mode = "r:gz" if file_name.endswith((".tar.gz", ".tgz")) else "r"
            with tarfile.open(file_path, mode) as tarf:
                for member in tarf.getmembers():
                    # Sanitize each member path to prevent directory traversal
                    safe_path = self._sanitize_archive_path(member.name, output_path)
                    if member.isfile():
                        # Extract file to sanitized path
                        member_data = tarf.extractfile(member)
                        if member_data:
                            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                            with open(safe_path, 'wb') as f:
                                shutil.copyfileobj(member_data, f)
                            extracted_files.append(self._get_relative_path(safe_path))
                    elif member.isdir():
                        # Create directory
                        os.makedirs(safe_path, exist_ok=True)
        else:
            raise ValueError("Unsupported archive format")
        
        return extracted_files

    async def save_file_version(self, file_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Save a version of the file.
        :param file_name: The name of the file to save a version of.
        :param base_dir: The base directory where the file is located.
        :return: A success message if the version is saved successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="version_save",
                    subject_type="file",
                    error="File does not exist",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(False, action="version_save", subject_type="file", error="Path is not a file")
            
            # Skip symlinks for security
            if await aiofiles.os.path.islink(file_path):
                return self._result(False, action="version_save", subject_type="file", error="Cannot version symlinks")
            
            # Use resolved path as key to avoid collisions
            version_key = file_path
            version_index = len(self.versions[version_key]) + 1
            
            # Create version filename with timestamp to avoid collisions
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name, ext = os.path.splitext(file_name)
            version_name = f"{base_name}_v{version_index}_{timestamp}{ext}"
            version_path = self._resolve_under_restriction(os.path.join(base_path, version_name))
            
            await asyncio.to_thread(shutil.copy2, file_path, version_path)
            self.versions[version_key].append(version_path)
            
            logger.info(f"Version saved for file '{file_name}' at {version_path}")
            return self._result(
                True,
                action="version_save",
                subject_type="file",
                message="Version saved",
                version=version_index,
                version_path=self._get_relative_path(version_path),
                original_path=self._get_relative_path(file_path)
            )
        except ValueError as e:
            return self._result(False, action="version_save", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="version_save", subject_type="file", error=f"Failed to save version: {str(e)}")

    async def restore_file_version(
        self, file_name: str, version: int, base_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Restore a file to a previous version.
        :param file_name: The name of the file to restore.
        :param version: The version number to restore.
        :param base_dir: The base directory where the file is located.
        :return: A success message if the file is restored successfully.
        """
        try:
            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            # Use resolved path as key
            version_key = file_path
            available_versions = len(self.versions[version_key])
            
            if version < 1 or version > available_versions:
                return self._result(
                    False,
                    action="version_restore",
                    subject_type="file",
                    error="Version does not exist",
                    available=available_versions,
                    requested=version
                )
            
            version_path = self.versions[version_key][version - 1]
            
            if not await aiofiles.os.path.exists(version_path):
                return self._result(
                    False,
                    action="version_restore",
                    subject_type="file",
                    error="Version file no longer exists",
                    version_path=self._get_relative_path(version_path)
                )
            
            # Restore even if original doesn't exist (recreate it)
            await self._ensure_parent_dir(file_path)
            await asyncio.to_thread(shutil.copy2, version_path, file_path)
            
            logger.info(f"File '{file_name}' restored to version {version} at {file_path}")
            return self._result(
                True,
                action="version_restore",
                subject_type="file",
                message="Restored",
                path=self._get_relative_path(file_path),
                version=version,
                version_path=self._get_relative_path(version_path)
            )
        except ValueError as e:
            return self._result(False, action="version_restore", subject_type="file", error=str(e))
        except OSError as e:
            return self._result(False, action="version_restore", subject_type="file", error=f"Failed to restore version: {str(e)}")

    async def search_files(
        self,
        keyword: str,
        base_dir: Optional[str] = None,
        case_sensitive: bool = True,
        include_content: bool = True,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """
        Search for files containing the keyword in their names or content.
        :param keyword: The keyword to search for.
        :param base_dir: The base directory where to search for files.
        :param case_sensitive: Whether the search should be case sensitive.
        :param include_content: Whether to search file contents (only text files).
        :param max_results: Maximum number of results to return.
        :return: A list of file paths that match the search criteria.
        """
        try:
            base_path = base_dir if base_dir else "."
            search_path = self._resolve_under_restriction(base_path)
            
            if not await aiofiles.os.path.exists(search_path):
                return self._result(
                    False,
                    action="search",
                    subject_type="directory",
                    error="Path must be an existing directory",
                    path=self._get_relative_path(search_path)
                )
            
            if not await aiofiles.os.path.isdir(search_path):
                return self._result(False, action="search", subject_type="directory", error="Path is not a directory")
            
            search_keyword = keyword if case_sensitive else keyword.lower()
            matches = []
            
            # Use asyncio.to_thread for the file walking operation
            matches = await asyncio.to_thread(
                self._search_files_sync,
                search_path,
                search_keyword,
                case_sensitive,
                include_content,
                max_results
            )
            
            logger.info(f"Search for keyword '{keyword}' completed with {len(matches)} matches")
            return self._result(
                True,
                action="search",
                subject_type="directory",
                count=len(matches),
                matches=matches,
                keyword=keyword,
                case_sensitive=case_sensitive,
                truncated=len(matches) >= max_results
            )
        except ValueError as e:
            return self._result(False, action="search", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="search", subject_type="directory", error=f"Failed to search: {str(e)}")
    
    def _search_files_sync(self, search_path: str, search_keyword: str, case_sensitive: bool, include_content: bool, max_results: int) -> List[Dict[str, Any]]:
        """Synchronous helper method for file searching."""
        matches = []
        
        for root, dirs, files in os.walk(search_path, followlinks=False):
            # Remove symlinked directories from dirs to prevent following them
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            
            for fname in files:
                if len(matches) >= max_results:
                    break
                    
                fpath = os.path.join(root, fname)
                
                # Skip symlinks for security
                if os.path.islink(fpath):
                    continue
                
                try:
                    # Check filename match
                    check_name = fname if case_sensitive else fname.lower()
                    name_match = search_keyword in check_name
                    content_match = False
                    
                    # Check content match if requested and file is not too large
                    if include_content and not name_match:
                        try:
                            file_size = os.path.getsize(fpath)
                            if file_size <= self.valves.max_search_file_size:
                                # Check if file is binary first
                                with open(fpath, 'rb') as f:
                                    chunk = f.read(1024)
                                    is_binary = b'\0' in chunk
                                
                                if not is_binary:
                                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                        content = f.read()
                                        check_content = content if case_sensitive else content.lower()
                                        content_match = search_keyword in check_content
                        except Exception:
                            # Skip files that can't be read
                            continue
                    
                    if name_match or content_match:
                        matches.append({
                            "path": self._get_relative_path(fpath),
                            "name": fname,
                            "match_type": "name" if name_match else "content",
                            "size": os.path.getsize(fpath)
                        })
                except Exception:
                    # Skip files that cause errors
                    continue
            
            if len(matches) >= max_results:
                break
        
        return matches

    async def search_file_names(
        self,
        pattern: str,
        base_dir: Optional[str] = None,
        case_sensitive: bool = True,
        include_extensions: bool = True,
        max_results: int = 100
    ) -> Dict[str, Any]:
        """
        Search for files by name and/or extension only (no content search).
        :param pattern: The pattern to search for in file names/extensions.
        :param base_dir: The base directory where to search for files.
        :param case_sensitive: Whether the search should be case sensitive.
        :param include_extensions: Whether to search in file extensions as well as names.
        :param max_results: Maximum number of results to return.
        :return: A list of file paths that match the search criteria.
        """
        try:
            base_path = base_dir if base_dir else "."
            search_path = self._resolve_under_restriction(base_path)
            
            if not await aiofiles.os.path.exists(search_path):
                return self._result(
                    False,
                    action="search_file_names",
                    subject_type="directory",
                    error="Path must be an existing directory",
                    path=self._get_relative_path(search_path)
                )
            
            if not await aiofiles.os.path.isdir(search_path):
                return self._result(False, action="search_file_names", subject_type="directory", error="Path is not a directory")
            
            search_pattern = pattern if case_sensitive else pattern.lower()
            matches = []
            
            # Use asyncio.to_thread for the file walking operation
            matches = await asyncio.to_thread(
                self._search_file_names_sync,
                search_path,
                search_pattern,
                case_sensitive,
                include_extensions,
                max_results
            )
            
            logger.info(f"File name search for pattern '{pattern}' completed with {len(matches)} matches")
            return self._result(
                True,
                action="search_file_names",
                subject_type="directory",
                count=len(matches),
                matches=matches,
                pattern=pattern,
                case_sensitive=case_sensitive,
                include_extensions=include_extensions,
                truncated=len(matches) >= max_results
            )
        except ValueError as e:
            return self._result(False, action="search_file_names", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="search_file_names", subject_type="directory", error=f"Failed to search: {str(e)}")
    
    def _search_file_names_sync(self, search_path: str, search_pattern: str, case_sensitive: bool, include_extensions: bool, max_results: int) -> List[Dict[str, Any]]:
        """Synchronous helper method for file name searching."""
        matches = []
        
        for root, dirs, files in os.walk(search_path, followlinks=False):
            # Remove symlinked directories from dirs to prevent following them
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            
            for fname in files:
                if len(matches) >= max_results:
                    break
                    
                fpath = os.path.join(root, fname)
                
                # Skip symlinks for security
                if os.path.islink(fpath):
                    continue
                
                try:
                    # Check filename match
                    check_name = fname if case_sensitive else fname.lower()
                    name_match = search_pattern in check_name
                    
                    # Check extension match if requested
                    extension_match = False
                    if include_extensions and not name_match:
                        # Get file extension (including the dot)
                        _, ext = os.path.splitext(fname)
                        if ext:  # Only check if there's an extension
                            check_ext = ext if case_sensitive else ext.lower()
                            extension_match = search_pattern in check_ext
                    
                    if name_match or extension_match:
                        # Get file size and other info
                        file_size = os.path.getsize(fpath)
                        _, ext = os.path.splitext(fname)
                        
                        matches.append({
                            "path": self._get_relative_path(fpath),
                            "name": fname,
                            "extension": ext if ext else None,
                            "match_type": "name" if name_match else "extension",
                            "size": file_size
                        })
                except Exception:
                    # Skip files that cause errors
                    continue
            
            if len(matches) >= max_results:
                break
        
        return matches

    async def synchronize_files(self, source_path: str, destination_path: str) -> Dict[str, Any]:
        """
        Synchronize files between two directories.
        :param source_path: The source directory to synchronize from.
        :param destination_path: The destination directory to synchronize to.
        :return: A success message if the synchronization is completed successfully.
        """
        try:
            source_path = self._resolve_under_restriction(source_path)
            destination_path = self._resolve_under_restriction(destination_path)
            
            if not await aiofiles.os.path.exists(source_path):
                return self._result(
                    False,
                    action="sync",
                    subject_type="directory",
                    error="Source directory does not exist",
                    src=self._get_relative_path(source_path)
                )
            
            if not await aiofiles.os.path.exists(destination_path):
                return self._result(
                    False,
                    action="sync",
                    subject_type="directory",
                    error="Destination directory does not exist",
                    dst=self._get_relative_path(destination_path)
                )
            
            if not await aiofiles.os.path.isdir(source_path) or not await aiofiles.os.path.isdir(destination_path):
                return self._result(False, action="sync", subject_type="directory", error="Both paths must be directories")
            
            # Use asyncio.to_thread for the synchronization operation
            copied, failed = await asyncio.to_thread(self._sync_files, source_path, destination_path)
            
            logger.info(f"Synchronization from '{source_path}' to '{destination_path}' completed: {copied} copied, {len(failed)} failed")
            return self._result(
                True,
                action="sync",
                subject_type="directory",
                message="Synchronized",
                copied=copied,
                failed=failed,
                src=self._get_relative_path(source_path),
                dst=self._get_relative_path(destination_path)
            )
        except ValueError as e:
            return self._result(False, action="sync", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="sync", subject_type="directory", error=f"Failed to synchronize: {str(e)}")
    
    def _sync_files(self, source_path: str, destination_path: str) -> tuple[int, List[Dict[str, str]]]:
        """Synchronous helper method for file synchronization."""
        copied = 0
        failed = []
        
        for root, dirs, files in os.walk(source_path, followlinks=False):
            # Remove symlinked directories from dirs to prevent following them
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            
            for fname in files:
                sfile = os.path.join(root, fname)
                
                # Skip symlinks for security
                if os.path.islink(sfile):
                    continue
                
                try:
                    rel = os.path.relpath(sfile, source_path)
                    dfile = os.path.join(destination_path, rel)
                    
                    # Ensure parent directory exists
                    parent_dir = os.path.dirname(dfile)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok=True)
                    
                    # Copy if destination doesn't exist or source is newer/different size
                    should_copy = False
                    if not os.path.exists(dfile):
                        should_copy = True
                    else:
                        src_stat = os.stat(sfile)
                        dst_stat = os.stat(dfile)
                        # Copy if source is newer or different size
                        if src_stat.st_mtime > dst_stat.st_mtime or src_stat.st_size != dst_stat.st_size:
                            should_copy = True
                    
                    if should_copy:
                        shutil.copy2(sfile, dfile)
                        copied += 1
                except OSError as e:
                    failed.append({"file": self._get_relative_path(sfile), "error": str(e)})
        
        return copied, failed

    async def backup_files(self, source_path: str, backup_path: str) -> Dict[str, Any]:
        """
        Backup files from the source directory to the backup directory.
        :param source_path: The source directory to backup from.
        :param backup_path: The backup directory to backup to.
        :return: A success message if the backup is completed successfully.
        """
        try:
            source_path = self._resolve_under_restriction(source_path)
            backup_path = self._resolve_under_restriction(backup_path)
            
            if not await aiofiles.os.path.exists(source_path):
                return self._result(
                    False,
                    action="backup",
                    subject_type="directory",
                    error="Source directory does not exist",
                    src=self._get_relative_path(source_path)
                )
            
            if not await aiofiles.os.path.isdir(source_path):
                return self._result(False, action="backup", subject_type="directory", error="Source path is not a directory")
            
            # Create backup directory if it doesn't exist
            await aiofiles.os.makedirs(backup_path, exist_ok=True)
            
            # Use asyncio.to_thread for the backup operation
            count, failed = await asyncio.to_thread(self._backup_files, source_path, backup_path)
            
            logger.info(f"Backup from '{source_path}' to '{backup_path}' completed: {count} files, {len(failed)} failed")
            return self._result(
                True,
                action="backup",
                subject_type="directory",
                message="Backup completed",
                files=count,
                failed=failed,
                src=self._get_relative_path(source_path),
                backup=self._get_relative_path(backup_path)
            )
        except ValueError as e:
            return self._result(False, action="backup", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="backup", subject_type="directory", error=f"Failed to backup: {str(e)}")
    
    def _backup_files(self, source_path: str, backup_path: str) -> tuple[int, List[Dict[str, str]]]:
        """Synchronous helper method for file backup."""
        count = 0
        failed = []
        
        for root, dirs, files in os.walk(source_path, followlinks=False):
            # Remove symlinked directories from dirs to prevent following them
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            
            for fname in files:
                sfile = os.path.join(root, fname)
                
                # Skip symlinks for security
                if os.path.islink(sfile):
                    continue
                
                try:
                    rel = os.path.relpath(sfile, source_path)
                    bfile = os.path.join(backup_path, rel)
                    parent_dir = os.path.dirname(bfile)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok=True)
                    shutil.copy2(sfile, bfile)
                    count += 1
                except OSError as e:
                    failed.append({"file": self._get_relative_path(sfile), "error": str(e)})
        
        return count, failed

    async def recover_files(self, backup_path: str, destination_path: str) -> Dict[str, Any]:
        """
        Recover files from the backup directory to the destination directory.
        :param backup_path: The backup directory to recover from.
        :param destination_path: The destination directory to recover to.
        :return: A success message if the recovery is completed successfully.
        """
        try:
            backup_path = self._resolve_under_restriction(backup_path)
            destination_path = self._resolve_under_restriction(destination_path)
            
            if not await aiofiles.os.path.exists(backup_path):
                return self._result(
                    False,
                    action="recover",
                    subject_type="directory",
                    error="Backup directory does not exist",
                    backup=self._get_relative_path(backup_path)
                )
            
            if not await aiofiles.os.path.isdir(backup_path):
                return self._result(False, action="recover", subject_type="directory", error="Backup path is not a directory")
            
            # Create destination directory if it doesn't exist
            await aiofiles.os.makedirs(destination_path, exist_ok=True)
            
            # Use asyncio.to_thread for the recovery operation
            count, failed = await asyncio.to_thread(self._recover_files, backup_path, destination_path)
            
            logger.info(f"Recovery from '{backup_path}' to '{destination_path}' completed: {count} files, {len(failed)} failed")
            return self._result(
                True,
                action="recover",
                subject_type="directory",
                message="Recovery completed",
                files=count,
                failed=failed,
                backup=self._get_relative_path(backup_path),
                dst=self._get_relative_path(destination_path)
            )
        except ValueError as e:
            return self._result(False, action="recover", subject_type="directory", error=str(e))
        except OSError as e:
            return self._result(False, action="recover", subject_type="directory", error=f"Failed to recover: {str(e)}")
    
    def _recover_files(self, backup_path: str, destination_path: str) -> tuple[int, List[Dict[str, str]]]:
        """Synchronous helper method for file recovery."""
        count = 0
        failed = []
        
        for root, dirs, files in os.walk(backup_path, followlinks=False):
            # Remove symlinked directories from dirs to prevent following them
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            
            for fname in files:
                bfile = os.path.join(root, fname)
                
                # Skip symlinks for security
                if os.path.islink(bfile):
                    continue
                
                try:
                    rel = os.path.relpath(bfile, backup_path)
                    dfile = os.path.join(destination_path, rel)
                    parent_dir = os.path.dirname(dfile)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok=True)
                    shutil.copy2(bfile, dfile)
                    count += 1
                except OSError as e:
                    failed.append({"file": self._get_relative_path(bfile), "error": str(e)})
        
        return count, failed

    def _get_supported_file_types(self) -> List[str]:
        """Get list of file types supported by OpenRouter vision models."""
        return [
            "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp",
            "application/pdf", "text/plain", "text/markdown", "text/csv",
            "application/json", "text/html", "text/xml",
            "audio/wav", "audio/mp3"
        ]

    def _is_file_supported_by_openrouter(self, mime_type: str) -> bool:
        """Check if file type is supported by OpenRouter models."""
        return mime_type in self._get_supported_file_types()

    async def _upload_file_to_openrouter(
        self,
        file_name: str,
        prompt: str = "Please analyze this file",
        base_dir: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1000
    ) -> Dict[str, Any]:
        """
        Upload a file to OpenRouter for analysis by a vision-capable model.
        :param file_name: The name of the file to upload and analyze.
        :param prompt: The prompt to send along with the file.
        :param base_dir: The base directory where the file is located.
        :param model: The OpenRouter model to use (overrides default).
        :param max_tokens: Maximum tokens for the response.
        :return: The model's analysis of the file.
        """
        try:
            # Check if API key is configured
            if not self.valves.openrouter_api_key:
                return self._result(
                    False,
                    action="openrouter_upload",
                    subject_type="file",
                    error="OpenRouter API key not configured. Please set openrouter_api_key in valves."
                )

            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="openrouter_upload",
                    subject_type="file",
                    error="File not found",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(
                    False,
                    action="openrouter_upload",
                    subject_type="file",
                    error="Path is not a file"
                )

            # Get file info and check if supported
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = "application/octet-stream"

            if not self._is_file_supported_by_openrouter(mime_type):
                return self._result(
                    False,
                    action="openrouter_upload",
                    subject_type="file",
                    error=f"File type '{mime_type}' not supported by OpenRouter models",
                    supported_types=self._get_supported_file_types()
                )

            # Read file content
            async with aiofiles.open(file_path, "rb") as f:
                file_content = await f.read()

            # Prepare the request
            model_name = model or self.valves.openrouter_model
            base64_content = base64.b64encode(file_content).decode('utf-8')
            
            # Construct message based on file type
            if mime_type.startswith('image/'):
                # For images, use vision format
                messages = [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:{mime_type};base64,{base64_content}"
                                }
                            }
                        ]
                    }
                ]
            elif mime_type == "application/pdf":
                # For PDFs, use the file format with plugin support
                data_url = f"data:application/pdf;base64,{base64_content}"
                messages = [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            },
                            {
                                "type": "file",
                                "file": {
                                    "filename": file_name,
                                    "file_data": data_url
                                }
                            }
                        ]
                    }
                ]
            elif mime_type.startswith('audio/'):
                # For audio files, use input_audio format
                # Extract format from mime type (e.g., "audio/wav" -> "wav")
                audio_format = mime_type.split('/')[-1]
                # Handle common audio format mappings
                if audio_format == "mpeg":
                    audio_format = "mp3"
                elif audio_format == "x-m4a":
                    audio_format = "m4a"
                
                messages = [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            },
                            {
                                "type": "input_audio",
                                "input_audio": {
                                    "data": base64_content,
                                    "format": audio_format
                                }
                            }
                        ]
                    }
                ]
            else:
                # For other documents, include content as text context
                try:
                    content_text = file_content.decode('utf-8')
                except UnicodeDecodeError:
                    content_text = f"[Binary File: {file_name}]\nBase64 Content: {base64_content[:100]}..."
                
                messages = [
                    {
                        "role": "user",
                        "content": f"{prompt}\n\nFile: {file_name}\nContent:\n{content_text}"
                    }
                ]

            # Make API request
            headers = {
                "Authorization": f"Bearer {self.valves.openrouter_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/jojomaw/filesystem",  # Required by OpenRouter
                "X-Title": "Filesystem Tool"  # Optional but recommended
            }

            payload = {
                "model": model_name,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": 0.7
            }
            
            # Add plugins configuration for PDF files
            if mime_type == "application/pdf":
                payload["plugins"] = [
                    {
                        "id": "file-parser",
                        "pdf": {
                            "engine": "pdf-text"  # defaults to "mistral-ocr"
                        }
                    }
                ]

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.valves.openrouter_base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Extract the response content
                        if "choices" in result and len(result["choices"]) > 0:
                            analysis = result["choices"][0]["message"]["content"]
                            
                            logger.info(f"File '{file_name}' successfully analyzed by OpenRouter model '{model_name}'")
                            return self._result(
                                True,
                                action="openrouter_upload",
                                subject_type="file",
                                path=self._get_relative_path(file_path),
                                model=model_name,
                                mime_type=mime_type,
                                file_size=len(file_content),
                                prompt=prompt,
                                analysis=analysis,
                                usage=result.get("usage", {}),
                                response_id=result.get("id", "")
                            )
                        else:
                            return self._result(
                                False,
                                action="openrouter_upload",
                                subject_type="file",
                                error="No response content received from OpenRouter",
                                response=result
                            )
                    else:
                        error_msg = f"OpenRouter API error: {response.status}"
                        try:
                            error_detail = await response.json()
                            error_msg += f" - {error_detail.get('error', {}).get('message', 'Unknown error')}"
                        except:
                            error_text = await response.text()
                            error_msg += f" - {error_text}"
                        
                        return self._result(
                            False,
                            action="openrouter_upload",
                            subject_type="file",
                            error=error_msg,
                            status_code=response.status
                        )

        except aiohttp.ClientError as e:
            return self._result(
                False,
                action="openrouter_upload",
                subject_type="file",
                error=f"Network error: {str(e)}"
            )
        except ValueError as e:
            return self._result(
                False,
                action="openrouter_upload",
                subject_type="file",
                error=str(e)
            )
        except Exception as e:
            return self._result(
                False,
                action="openrouter_upload",
                subject_type="file",
                error=f"Unexpected error: {str(e)}"
            )

    async def batch_upload_files_to_openrouter(
        self,
        file_names: List[str],
        prompt: str = "Please analyze these files",
        base_dir: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1000
    ) -> Dict[str, Any]:
        """
        Upload multiple files to OpenRouter for batch analysis.
        :param file_names: List of file names to upload and analyze.
        :param prompt: The prompt to send along with the files.
        :param base_dir: The base directory where the files are located.
        :param model: The OpenRouter model to use (overrides default).
        :param max_tokens: Maximum tokens for the response.
        :return: Results for each file analysis.
        """
        try:
            if not file_names:
                return self._result(
                    False,
                    action="openrouter_batch_upload",
                    subject_type="files",
                    error="No files specified for batch upload"
                )

            results = []
            successful = 0
            failed = 0

            for file_name in file_names:
                result = await self._upload_file_to_openrouter(
                    file_name=file_name,
                    prompt=prompt,
                    base_dir=base_dir,
                    model=model,
                    max_tokens=max_tokens
                )
                
                results.append({
                    "file": file_name,
                    "success": result["ok"],
                    "result": result
                })
                
                if result["ok"]:
                    successful += 1
                else:
                    failed += 1

            logger.info(f"Batch upload completed: {successful} successful, {failed} failed")
            return self._result(
                True,
                action="openrouter_batch_upload",
                subject_type="files",
                total_files=len(file_names),
                successful=successful,
                failed=failed,
                results=results
            )

        except Exception as e:
            return self._result(
                False,
                action="openrouter_batch_upload",
                subject_type="files",
                error=f"Batch upload error: {str(e)}"
            )

    async def transcribe_file(
        self,
        file_name: str,
        base_dir: Optional[str] = None,
        transcription_mode: str = "auto",
        language: Optional[str] = None,
        output_format: str = "text"
    ) -> Dict[str, Any]:
        """
        Transcribe text content from any supported file type using OpenRouter models.
        Supports OCR for images, text extraction from PDFs, and direct text reading.
        
        :param file_name: The name of the file to transcribe.
        :param base_dir: The base directory where the file is located.
        :param transcription_mode: Mode of transcription ('auto', 'ocr', 'extract', 'read').
        :param language: Expected language of the text (optional hint).
        :param output_format: Output format ('text', 'markdown', 'structured').
        :return: Transcribed text content and metadata.
        """
        try:
            # Check if API key is configured
            if not self.valves.openrouter_api_key:
                return self._result(
                    False,
                    action="transcribe",
                    subject_type="file",
                    error="OpenRouter API key not configured. Please set openrouter_api_key in valves."
                )

            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="transcribe",
                    subject_type="file",
                    error="File not found",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(
                    False,
                    action="transcribe",
                    subject_type="file",
                    error="Path is not a file"
                )

            # Get file info
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = "application/octet-stream"

            # Determine transcription strategy based on file type and mode
            if transcription_mode == "auto":
                if mime_type.startswith('image/'):
                    transcription_mode = "ocr"
                elif mime_type == "application/pdf":
                    transcription_mode = "extract"
                elif mime_type.startswith('text/'):
                    transcription_mode = "read"
                else:
                    transcription_mode = "extract"

            # Build appropriate prompt based on mode and format
            if transcription_mode == "ocr":
                if output_format == "markdown":
                    prompt = "Please perform OCR on this image and return the text in clean Markdown format. Preserve any formatting, headers, lists, and structure you can identify."
                elif output_format == "structured":
                    prompt = "Please perform OCR on this image and return the text in a structured format with clear sections, headers, and organization. Include any tables, lists, or special formatting."
                else:
                    prompt = "Please perform OCR on this image and extract all visible text. Return only the text content, preserving line breaks and basic formatting."
                    
            elif transcription_mode == "extract":
                if output_format == "markdown":
                    prompt = "Please extract and transcribe all text content from this document and format it as clean Markdown. Preserve headings, lists, tables, and document structure."
                elif output_format == "structured":
                    prompt = "Please extract all text from this document and organize it in a clear, structured format with proper sections, headings, and formatting."
                else:
                    prompt = "Please extract and transcribe all text content from this document. Return the complete text preserving paragraphs and basic formatting."
                    
            elif transcription_mode == "read":
                # For text files, we can read directly but still use AI for formatting
                if output_format == "markdown":
                    prompt = "Please convert this text content to clean Markdown format, adding appropriate headers and formatting where suitable."
                elif output_format == "structured":
                    prompt = "Please organize this text content into a well-structured format with clear sections and formatting."
                else:
                    prompt = "Please clean up and format this text content, preserving the original meaning and structure."
            else:
                return self._result(
                    False,
                    action="transcribe",
                    subject_type="file",
                    error=f"Unsupported transcription mode: {transcription_mode}"
                )

            # Add language hint if provided
            if language:
                prompt += f" The text is expected to be in {language}."

            # Use the existing OpenRouter upload method
            result = await self._upload_file_to_openrouter(
                file_name=file_name,
                prompt=prompt,
                base_dir=base_dir,
                max_tokens=10000  # Higher token limit for transcription
            )

            if result["ok"]:
                transcribed_text = result.get("analysis", "")
                
                # Post-process the transcribed text
                if output_format == "text":
                    # Clean up any markdown formatting if we just want plain text
                    import re
                    transcribed_text = re.sub(r'[#*_`]', '', transcribed_text)
                    transcribed_text = re.sub(r'\n\s*\n', '\n\n', transcribed_text)

                logger.info(f"File '{file_name}' transcribed successfully using mode '{transcription_mode}'")
                return self._result(
                    True,
                    action="transcribe",
                    subject_type="file",
                    path=self._get_relative_path(file_path),
                    transcribed_text=transcribed_text,
                    transcription_mode=transcription_mode,
                    output_format=output_format,
                    mime_type=mime_type,
                    model=result.get("model", ""),
                    file_size=result.get("file_size", 0),
                    language=language,
                    word_count=len(transcribed_text.split()) if transcribed_text else 0,
                    character_count=len(transcribed_text) if transcribed_text else 0,
                    usage=result.get("usage", {})
                )
            else:
                return self._result(
                    False,
                    action="transcribe",
                    subject_type="file",
                    error=f"Transcription failed: {result.get('error', 'Unknown error')}",
                    path=self._get_relative_path(file_path)
                )

        except ValueError as e:
            return self._result(
                False,
                action="transcribe",
                subject_type="file",
                error=str(e)
            )
        except Exception as e:
            return self._result(
                False,
                action="transcribe",
                subject_type="file",
                error=f"Unexpected error during transcription: {str(e)}"
            )

    async def batch_transcribe_files(
        self,
        file_names: List[str],
        base_dir: Optional[str] = None,
        transcription_mode: str = "auto",
        language: Optional[str] = None,
        output_format: str = "text"
    ) -> Dict[str, Any]:
        """
        Transcribe multiple files in batch using OpenRouter models.
        
        :param file_names: List of file names to transcribe.
        :param base_dir: The base directory where the files are located.
        :param transcription_mode: Mode of transcription ('auto', 'ocr', 'extract', 'read').
        :param language: Expected language of the text (optional hint).
        :param output_format: Output format ('text', 'markdown', 'structured').
        :return: Results for each file transcription.
        """
        try:
            if not file_names:
                return self._result(
                    False,
                    action="batch_transcribe",
                    subject_type="files",
                    error="No files specified for batch transcription"
                )

            results = []
            successful = 0
            failed = 0
            total_words = 0
            total_characters = 0

            for file_name in file_names:
                result = await self.transcribe_file(
                    file_name=file_name,
                    base_dir=base_dir,
                    transcription_mode=transcription_mode,
                    language=language,
                    output_format=output_format
                )
                
                results.append({
                    "file": file_name,
                    "success": result["ok"],
                    "result": result
                })
                
                if result["ok"]:
                    successful += 1
                    total_words += result.get("word_count", 0)
                    total_characters += result.get("character_count", 0)
                else:
                    failed += 1

            logger.info(f"Batch transcription completed: {successful} successful, {failed} failed")
            return self._result(
                True,
                action="batch_transcribe",
                subject_type="files",
                total_files=len(file_names),
                successful=successful,
                failed=failed,
                total_words=total_words,
                total_characters=total_characters,
                transcription_mode=transcription_mode,
                output_format=output_format,
                language=language,
                results=results
            )

        except Exception as e:
            return self._result(
                False,
                action="batch_transcribe",
                subject_type="files",
                error=f"Batch transcription error: {str(e)}"
            )

    async def describe_image(
        self,
        file_name: str,
        base_dir: Optional[str] = None,
        description_type: str = "detailed",
        model: Optional[str] = None,
        max_tokens: int = 1000
    ) -> Dict[str, Any]:
        """
        Describe an image using OpenRouter vision models.
        
        :param file_name: The name of the image file to describe.
        :param base_dir: The base directory where the image is located.
        :param description_type: Type of description ('detailed', 'brief', 'technical', 'creative').
        :param model: The OpenRouter model to use (overrides default).
        :param max_tokens: Maximum tokens for the response.
        :return: Image description and metadata.
        """
        try:
            # Check if API key is configured
            if not self.valves.openrouter_api_key:
                return self._result(
                    False,
                    action="describe_image",
                    subject_type="file",
                    error="OpenRouter API key not configured. Please set openrouter_api_key in valves."
                )

            base_path = base_dir if base_dir else "."
            file_path = self._resolve_under_restriction(os.path.join(base_path, file_name))
            
            if not await aiofiles.os.path.exists(file_path):
                return self._result(
                    False,
                    action="describe_image",
                    subject_type="file",
                    error="Image file not found",
                    path=self._get_relative_path(file_path)
                )
            
            if not await aiofiles.os.path.isfile(file_path):
                return self._result(
                    False,
                    action="describe_image",
                    subject_type="file",
                    error="Path is not a file"
                )

            # Check if file is an image
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type or not mime_type.startswith('image/'):
                return self._result(
                    False,
                    action="describe_image",
                    subject_type="file",
                    error=f"File is not an image. Detected type: {mime_type or 'unknown'}",
                    path=self._get_relative_path(file_path)
                )

            # Build appropriate prompt based on description type
            if description_type == "detailed":
                prompt = "Please provide a detailed description of this image. Include information about the main subjects, setting, colors, composition, mood, and any notable details or elements you observe."
            elif description_type == "brief":
                prompt = "Please provide a brief, concise description of what you see in this image."
            elif description_type == "technical":
                prompt = "Please provide a technical analysis of this image, including composition, lighting, color palette, photographic techniques, and visual elements."
            elif description_type == "creative":
                prompt = "Please provide a creative, artistic description of this image. Focus on the mood, atmosphere, story, and emotional impact of the visual elements."
            else:
                prompt = f"Please describe this image with a focus on: {description_type}"

            # Use the existing OpenRouter upload method
            result = await self._upload_file_to_openrouter(
                file_name=file_name,
                prompt=prompt,
                base_dir=base_dir,
                model=model,
                max_tokens=max_tokens
            )

            if result["ok"]:
                description = result.get("analysis", "")
                
                logger.info(f"Image '{file_name}' described successfully using '{description_type}' style")
                return self._result(
                    True,
                    action="describe_image",
                    subject_type="file",
                    path=self._get_relative_path(file_path),
                    description=description,
                    description_type=description_type,
                    mime_type=mime_type,
                    model=result.get("model", ""),
                    file_size=result.get("file_size", 0),
                    word_count=len(description.split()) if description else 0,
                    character_count=len(description) if description else 0,
                    usage=result.get("usage", {}),
                    response_id=result.get("response_id", "")
                )
            else:
                return self._result(
                    False,
                    action="describe_image",
                    subject_type="file",
                    error=f"Image description failed: {result.get('error', 'Unknown error')}",
                    path=self._get_relative_path(file_path)
                )

        except ValueError as e:
            return self._result(
                False,
                action="describe_image",
                subject_type="file",
                error=str(e)
            )
        except Exception as e:
            return self._result(
                False,
                action="describe_image",
                subject_type="file",
                error=f"Unexpected error during image description: {str(e)}"
            )

    async def batch_describe_images(
        self,
        file_names: List[str],
        base_dir: Optional[str] = None,
        description_type: str = "detailed",
        model: Optional[str] = None,
        max_tokens: int = 1000
    ) -> Dict[str, Any]:
        """
        Describe multiple images in batch using OpenRouter vision models.
        
        :param file_names: List of image file names to describe.
        :param base_dir: The base directory where the images are located.
        :param description_type: Type of description ('detailed', 'brief', 'technical', 'creative').
        :param model: The OpenRouter model to use (overrides default).
        :param max_tokens: Maximum tokens for each response.
        :return: Results for each image description.
        """
        try:
            if not file_names:
                return self._result(
                    False,
                    action="batch_describe_images",
                    subject_type="files",
                    error="No image files specified for batch description"
                )

            results = []
            successful = 0
            failed = 0
            total_words = 0
            total_characters = 0

            for file_name in file_names:
                result = await self.describe_image(
                    file_name=file_name,
                    base_dir=base_dir,
                    description_type=description_type,
                    model=model,
                    max_tokens=max_tokens
                )
                
                results.append({
                    "file": file_name,
                    "success": result["ok"],
                    "result": result
                })
                
                if result["ok"]:
                    successful += 1
                    total_words += result.get("word_count", 0)
                    total_characters += result.get("character_count", 0)
                else:
                    failed += 1

            logger.info(f"Batch image description completed: {successful} successful, {failed} failed")
            return self._result(
                True,
                action="batch_describe_images",
                subject_type="files",
                total_files=len(file_names),
                successful=successful,
                failed=failed,
                total_words=total_words,
                total_characters=total_characters,
                description_type=description_type,
                model=model or self.valves.openrouter_model,
                results=results
            )

        except Exception as e:
            return self._result(
                False,
                action="batch_describe_images",
                subject_type="files",
                error=f"Batch image description error: {str(e)}"
            )