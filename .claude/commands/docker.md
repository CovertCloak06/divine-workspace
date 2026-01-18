Containerize application.

## Step 1: Analyze
Use the **devops** agent to understand:
- Runtime requirements
- Dependencies
- Build process
- Ports/volumes needed

## Step 2: Design
Plan container:
- Base image
- Build stages
- Environment handling
- Health checks

## Step 3: Implement
Create:
- Dockerfile (multi-stage)
- .dockerignore
- docker-compose.yml (if needed)

## Step 4: Optimize
- Minimize image size
- Layer caching
- Security hardening
- Non-root user

## Step 5: Test
- Image builds
- Container runs
- App works
- Health checks pass

## Step 6: Document
Use the **docs-writer** agent for Docker usage guide.
