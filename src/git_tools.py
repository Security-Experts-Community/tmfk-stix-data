from contextlib import contextmanager
from datetime import datetime
from typing import Iterator, Generator
from io import BytesIO

import git


def get_first_commit_date(repo_path: str) -> str:
    repo = git.Repo(repo_path)
    return list(repo.iter_commits(paths="LICENSE"))[-1].committed_datetime


def get_last_commit_hash(repo_path: str):
    repo = git.Repo(repo_path)
    return repo.commit("main").hexsha[:7]


def iter_file_commits(repo_path: str, file_path: str) -> Iterator[git.Commit]:
    repo = git.Repo(repo_path)
    return repo.iter_commits(paths=file_path)


def get_file_creation_date(repo_path: str, file_path: str) -> datetime | None:
    commits = list(iter_file_commits(repo_path, file_path))
    if commits and len(commits):
        return commits[-1].committed_datetime
    return None


def get_file_modification_date(repo_path: str, file_path: str) -> datetime | None:
    try:
        return next(iter_file_commits(repo_path, file_path)).committed_datetime
    except StopIteration:
        return None


@contextmanager
def open_file_at_commit(
    commit: git.Commit,
    file_path: str,
) -> Generator[BytesIO, None, None]:
    targetfile = commit.tree / file_path
    try:
        f = BytesIO(targetfile.data_stream.read())
        yield f
    finally:
        f.close()
