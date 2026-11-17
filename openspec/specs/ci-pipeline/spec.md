# ci-pipeline Specification

## Purpose
Define continuous integration checks for the repository and the gitflow conventions (branch model, PR size and direction) that govern how changes land.

## Requirements

### Requirement: CI workflow
The repository SHALL have a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs ruff check, ruff format check, and the pytest suite on every push and pull request affecting the `main` and `dev` branches.

#### Scenario: CI runs on PR
- **WHEN** a pull request is opened toward `dev` or `main`
- **THEN** CI runs lint checks and the full test suite and reports status on the PR

#### Scenario: CI runs on push
- **WHEN** a commit is pushed to `main` or `dev`
- **THEN** CI runs the same checks on the pushed commit

### Requirement: CI uses uv
The CI workflow SHALL set up Python via uv and install dependencies with `uv sync`, matching the local development workflow.

#### Scenario: Locked install in CI
- **WHEN** CI installs dependencies
- **THEN** it uses the committed `uv.lock` via uv rather than resolving requirements ad hoc

### Requirement: CI test matrix
The pytest suite SHALL run in CI across multiple supported Python versions from the declared support range (at least the minimum supported version and a recent stable version).

#### Scenario: Multiple interpreters
- **WHEN** CI completes for a commit
- **THEN** the test suite has passed on every version in the configured matrix

### Requirement: Gitflow branch model
The repository SHALL use a gitflow model with a long-lived `dev` integration branch and `main` as the stable branch; feature work happens on short-lived feature branches.

#### Scenario: Dev branch exists
- **WHEN** the repository branches are listed
- **THEN** a `dev` branch exists and is kept up to date with integration work

#### Scenario: Feature branches merge to dev
- **WHEN** a feature branch is ready
- **THEN** it is merged into `dev` via pull request, not directly into `main`

### Requirement: Small focused pull requests
Pull requests SHALL be small and focused on a single change (targeting on the order of tens to low hundreds of changed lines), with a clear title and description, so they are practical to review.

#### Scenario: Reviewable size
- **WHEN** a PR is opened
- **THEN** its diff is limited to one coherent improvement rather than a bulk multi-purpose change

### Requirement: Meaningful targeted commits
Commits SHALL be small, imperative-mood, and describe one purpose each (e.g., `Add uv packaging and lockfile`), avoiding mixed unrelated changes in a single commit.

#### Scenario: Commit hygiene
- **WHEN** the commit history of a merged PR is inspected
- **THEN** each commit covers a single purpose and its message describes it accurately
