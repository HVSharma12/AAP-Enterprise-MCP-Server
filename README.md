# AAP Enterprise MCP Server

A Model Context Protocol (MCP) server for Ansible Automation Platform (AAP) and Event-Driven Ansible (EDA), enabling AI assistants to interact with your automation infrastructure.

## Features

### Ansible Automation Platform (AAP) Integration
- **Inventory Management**: List, create, update inventories and manage hosts/groups
- **Job Management**: Run job templates, monitor job status, and retrieve logs
- **Project Management**: Create and manage SCM-based projects
- **Template Management**: Create and manage job templates
- **Host Operations**: Add/remove hosts, manage host variables and facts
- **Ad-hoc Commands**: Execute ansible commands directly on inventory hosts

### Event-Driven Ansible (EDA) Integration
- **Activation Management**: List, create, enable/disable EDA activations
- **Rulebook Management**: Manage and query rulebooks
- **Decision Environment Management**: Manage decision environments
- **Event Stream Monitoring**: Monitor event streams

### Ansible Galaxy Integration
- **Collection Search**: Search and discover Ansible collections by name, namespace, or keywords
- **Role Search**: Find community roles by keyword, author, or specific criteria
- **Content Details**: Get comprehensive information about collections and roles including versions, dependencies, and installation instructions
- **Smart Suggestions**: AI-powered content recommendations based on use case descriptions
- **AAP Integration**: Intelligent suggestions that consider existing AAP infrastructure and inventories

### Ansible Lint Integration
- **Playbook Validation**: Real-time linting of Ansible playbook content with configurable quality profiles
- **File Analysis**: Comprehensive analysis of Ansible files, roles, and entire project structures
- **Best Practice Enforcement**: Automated checking against Ansible community standards and best practices
- **Syntax Validation**: Quick syntax checking for immediate feedback during development
- **Multi-Profile Support**: Progressive quality improvement with profiles from basic to production-ready
- **Rule Management**: List, filter, and understand ansible-lint rules with detailed explanations

## Installation

### Prerequisites
- Python 3.11 or higher
- UV package manager (recommended) or pip
- Access to an Ansible Automation Platform instance
- Valid AAP API token

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/sibilleb/AAP-Enterprise-MCP-Server.git
   cd AAP-Enterprise-MCP-Server
   ```

2. **Install dependencies**:
   ```bash
   # Using UV (recommended)
   uv sync
   
   # Or using pip
   pip install -e .
   ```

3. **Set up environment variables**:
   ```bash
   export AAP_TOKEN="your-aap-api-token"
   export AAP_URL="https://your-aap-server.com/api/controller/v2"
   export EDA_TOKEN="your-eda-api-token"  # Can be same as AAP_TOKEN
   export EDA_URL="https://your-aap-server.com/api/eda/v1"
   ```

## Getting Your API Token

### Method 1: AAP Web Interface
1. Log into your AAP web interface
2. Click on your username in the top right corner
3. Select "User Settings" or "My Profile"
4. Navigate to the "Tokens" section
5. Click "Add" or "Create Token"
6. Set the scope to "Write" for full functionality
7. Copy the generated token immediately (it won't be shown again)

### Method 2: Command Line
```bash
curl -k -X POST \
  "https://your-aap-server.com/api/v2/tokens/" \
  -H "Content-Type: application/json" \
  -u "username:password" \
  -d '{
    "description": "MCP Server Token",
    "application": null,
    "scope": "write"
  }'
```

## Configuration

### MCP Client Configuration

Add the following to your MCP client configuration (e.g., Claude Desktop, Cursor):

```json
{
  "mcpServers": {
    "ansible": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/AAP-Enterprise-MCP-Server",
        "run",
        "ansible.py"
      ],
      "env": {
        "AAP_TOKEN": "your-aap-api-token",
        "AAP_URL": "https://your-aap-server.com/api/controller/v2"
      }
    },
    "eda": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/AAP-Enterprise-MCP-Server",
        "run",
        "eda.py"
      ],
      "env": {
        "EDA_TOKEN": "your-eda-api-token",
        "EDA_URL": "https://your-aap-server.com/api/eda/v1"
      }
    },
    "ansible-lint": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/AAP-Enterprise-MCP-Server",
        "run",
        "ansible-lint.py"
      ]
    }
  }
}
```

### SSL/TLS Configuration

For lab environments with self-signed certificates, the servers automatically:
- Disable SSL warnings
- Skip certificate verification
- Handle insecure connections gracefully

For production environments, ensure proper SSL certificates are configured on your AAP instance.

## Available Tools

### Ansible Automation Platform Tools

| Tool | Description |
|------|-------------|
| `list_inventories` | List all inventories |
| `get_inventory` | Get inventory details by ID |
| `create_inventory` | Create a new inventory |
| `list_hosts` | List hosts in an inventory |
| `add_host_to_inventory` | Add a host to inventory |
| `run_job` | Execute a job template |
| `job_status` | Check job execution status |
| `job_logs` | Retrieve job execution logs |
| `list_job_templates` | List available job templates |
| `create_job_template` | Create a new job template |
| `create_project` | Create a new project |
| `run_adhoc_command` | Execute ad-hoc ansible commands |

### Ansible Galaxy Search Tools

| Tool | Description |
|------|-------------|
| `search_galaxy_collections` | Search Ansible Galaxy collections by query, tags, or namespace |
| `search_galaxy_roles` | Search Ansible Galaxy roles by keyword, name, or author |
| `get_collection_details` | Get detailed information about a specific collection |
| `get_role_details` | Get detailed information about a specific role |
| `suggest_ansible_content` | Intelligently suggest collections and roles based on use case description |

### Ansible Lint Tools

| Tool | Description |
|------|-------------|
| `lint_playbook` | Lint Ansible playbook content with configurable profiles and rules |
| `lint_file` | Lint specific Ansible files on disk |
| `lint_role` | Comprehensive validation of Ansible role directories |
| `validate_syntax` | Quick syntax-only validation for immediate feedback |
| `check_best_practices` | Context-aware best practice checking (dev/staging/production) |
| `analyze_project` | Analyze entire Ansible project structure with comprehensive reporting |
| `list_rules` | List available ansible-lint rules, optionally filtered by tags |
| `list_tags` | List all available tags for ansible-lint rules |
| `get_ansible_lint_version` | Get version information for installed ansible-lint |

### Event-Driven Ansible Tools

| Tool | Description |
|------|-------------|
| `list_activations` | List EDA activations |
| `get_activation` | Get activation details |
| `create_activation` | Create new activation |
| `enable_activation` | Enable an activation |
| `disable_activation` | Disable an activation |
| `restart_activation` | Restart an activation |
| `list_rulebooks` | List available rulebooks |
| `get_rulebook` | Get rulebook details |
| `list_decision_environments` | List decision environments |

## Usage Examples

### Running a Job Template
```python
# List available job templates
templates = await list_job_templates()

# Run a specific job template with variables
result = await run_job(
    template_id=5,
    extra_vars={"target_env": "production", "app_version": "1.2.3"}
)

# Check job status
status = await job_status(result["job"])
```

### Managing Inventory
```python
# List all inventories
inventories = await list_inventories()

# Add a new host to inventory
await add_host_to_inventory(
    inventory_id=1,
    hostname="web-server-01.example.com",
    variables={"ansible_host": "192.168.1.100", "role": "webserver"}
)

# Run ad-hoc command on inventory
await run_adhoc_command(
    inventory_id=1,
    module_name="setup",
    limit="web-server-01.example.com"
)
```

### Galaxy Content Discovery
```python
# Get intelligent suggestions for a specific use case
suggestions = await suggest_ansible_content(
    use_case="I am developing a playbook that spins up and down EC2 servers on AWS using ansible",
    check_aap_inventory=True
)

# Search for AWS-related collections
collections = await search_galaxy_collections(query="aws", limit=10)

# Search for EC2-specific roles
roles = await search_galaxy_roles(keyword="ec2", limit=5)

# Get detailed information about a specific collection
details = await get_collection_details(namespace="amazon", name="aws")

# Get detailed information about a specific role
role_info = await get_role_details(role_id=12345)
```

### Ansible Lint Quality Assurance
```python
# Lint playbook content with different quality profiles
playbook_content = """
---
- hosts: all
  tasks:
    - name: install package
      yum: name=nginx state=present
"""

# Basic linting for development
basic_results = await lint_playbook(
    content=playbook_content,
    profile="basic",
    format_type="json"
)

# Production-ready validation
production_results = await lint_playbook(
    content=playbook_content,
    profile="production",
    format_type="json"
)

# Quick syntax validation
syntax_check = await validate_syntax(content=playbook_content)

# Context-aware best practices checking
best_practices = await check_best_practices(
    content=playbook_content,
    context="production"
)

# Analyze entire project structure
project_analysis = await analyze_project(
    project_path="/path/to/ansible/project",
    profile="moderate"
)

# List available rules and tags
rules = await list_rules(tags="idempotency,syntax")
tags = await list_tags()
```

### EDA Activation Management
```python
# List all activations
activations = await list_activations()

# Enable a specific activation
await enable_activation(activation_id=3)

# Check activation details
details = await get_activation(activation_id=3)
```

## Development

### Running Tests
```bash
# Install development dependencies
uv sync --group dev

# Run tests
pytest

# Run with coverage
pytest --cov=.
```

### Code Formatting
```bash
# Format code
black .

# Lint code
ruff check .

# Type checking
mypy .
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors**: The server handles self-signed certificates automatically. If you encounter SSL issues, verify your AAP server configuration.

2. **Authentication Failures**: Ensure your API token has sufficient permissions (Write scope recommended).

3. **Connection Timeouts**: Check network connectivity to your AAP server and verify the URL format.

4. **Tool Not Found**: Restart your MCP client after configuration changes.

### Debug Mode

Set environment variable for verbose logging:
```bash
export MCP_DEBUG=1
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: [Report bugs and request features](https://github.com/sibilleb/AAP-Enterprise-MCP-Server/issues)
- Documentation: [README](README.md)
- Ansible Community: [Ansible Community Forum](https://forum.ansible.com/)

## Related Projects

- [Ansible Automation Platform](https://www.redhat.com/en/technologies/management/ansible)
- [Event-Driven Ansible](https://www.redhat.com/en/technologies/management/ansible/event-driven-ansible)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [FastMCP](https://github.com/punkpeye/fastmcp)
- [MCP](https://github.com/rlopez133/mcp)