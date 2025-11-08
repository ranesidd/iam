## Description

<!-- Provide a clear and concise description of what this PR does -->

## Related Issues

<!-- Link related issues below. Use "Closes #XX" to auto-close issues when PR is merged -->

- Closes #
- Fixes #
- Related to #

## Type of Change

<!-- Mark the relevant option with an "x" -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code refactoring (no functional changes)
- [ ] Performance improvement
- [ ] Test updates

## Changes Made

<!-- Describe the changes in detail. Use bullet points for clarity -->

-
-
-

## Testing

<!-- Describe the tests you ran and how to reproduce them -->

### Test Coverage

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass locally (`go test ./...`)

### Test Commands Run

```bash
# Example:
go test ./google_iam -v
go test ./otp -v
go test -tags=integration ./google_iam -v
```

### Test Results

<!-- Paste relevant test output or describe what was tested -->

```
# Paste test output here
```

## Database Changes (if applicable)

<!-- If this PR includes database schema changes, describe them here -->

- [ ] Schema changes required
- [ ] Migration script provided
- [ ] Backward compatible

## Breaking Changes

<!-- If this PR introduces breaking changes, describe them and the migration path -->

**Are there breaking changes?** No / Yes

<!-- If yes, describe:
- What breaks
- Why the breaking change is necessary
- How users should migrate their code
-->

## Checklist

<!-- Mark completed items with an "x" -->

### Code Quality

- [ ] My code follows the project's style guidelines (see [CONTRIBUTING.md](../../CONTRIBUTING.md))
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings or errors
- [ ] Code has been formatted with `gofmt`
- [ ] Code has been checked with `go vet`

### Documentation

- [ ] I have updated the documentation accordingly
- [ ] I have updated [README.md](../../README.md) for user-facing changes
- [ ] I have updated [CLAUDE.md](../../CLAUDE.md) for architectural changes
- [ ] I have added/updated code comments for public APIs
- [ ] Docstrings follow Go documentation standards

### Testing

- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have added integration tests if applicable
- [ ] Test coverage has not decreased

### Compatibility

- [ ] My changes are backward compatible
- [ ] I have updated version numbers if needed
- [ ] I have updated go.mod dependencies if needed

### Security

- [ ] I have checked for security vulnerabilities
- [ ] No sensitive data (credentials, API keys) is committed
- [ ] Input validation has been added where necessary
- [ ] Error messages don't leak sensitive information

## Additional Context

<!-- Add any other context, screenshots, benchmarks, or information about the PR here -->

### Environment Tested

- Go Version:
- OS:
- Database (if OTP changes):

### Performance Impact

<!-- If applicable, describe any performance implications -->

- [ ] No performance impact
- [ ] Performance improved
- [ ] Performance degraded (explain why acceptable)

### Screenshots/Logs

<!-- If applicable, add screenshots or relevant logs -->

---

**Reviewer Guidelines:**

Please review for:
- Code quality and adherence to Go best practices
- Test coverage and quality
- Documentation completeness
- Security considerations
- Breaking change implications
- Performance impact
