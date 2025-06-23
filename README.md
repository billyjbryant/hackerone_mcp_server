# HackerOne MCP Server

A Model Context Protocol (MCP) server that provides seamless integration with HackerOne's bug bounty platform through Claude Desktop. This server enables security professionals to efficiently manage vulnerability reports, perform triage operations, and maintain compliance with security directives directly from Claude.

## Features

- **Comprehensive Report Management**: Fetch and analyze new reports, all reports, or specific reports by ID
- **Smart Duplicate Detection**: Advanced similarity analysis to identify potential duplicate reports
- **Scope Validation**: Automated checking of reports against program scope and policies  
- **Weekly Reporting**: Generate detailed weekly status reports with metrics and insights
- **MDC Compliance**: Built-in security directives and compliance checking for consistent operations
- **Zero-Knowledge Architecture Support**: Specialized handling for privacy-first security models

## Prerequisites

- Python 3.8 or higher
- Poetry (for dependency management)
- HackerOne API credentials
- Claude Desktop application

## Installation

### System Requirements

- **Python**: 3.8 or higher (3.9+ recommended)
- **Operating System**: macOS, Windows, or Linux
- **Memory**: 512MB RAM minimum for basic operation
- **Network**: Internet connection for HackerOne API access

### 1. Clone the Repository

```bash
git clone <repository-url>
cd hackerone-mcp
```

### 2. Install Dependencies

#### Option A: Using Poetry (Recommended)

Poetry provides better dependency management and virtual environment isolation.

```bash
# Install Poetry if you don't have it
curl -sSL https://install.python-poetry.org | python3 -

# Verify Poetry installation
poetry --version

# Install project dependencies
poetry install

# Verify installation
poetry run python --version
```

**Poetry Troubleshooting:**
- **Mac/Linux**: If `poetry` command not found, add `~/.local/bin` to your PATH
- **Windows**: Poetry might install to `%APPDATA%\Python\Scripts` - add to PATH
- **Permission Issues**: Use `python3 -m pip install --user poetry` as alternative

#### Option B: Using pip + venv

```bash
# Create virtual environment
python3 -m venv hackerone-mcp-env

# Activate virtual environment
# On macOS/Linux:
source hackerone-mcp-env/bin/activate
# On Windows:
hackerone-mcp-env\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install httpx python-dotenv pyyaml mcp

# Verify installation
python --version
pip list
```

#### Required Python Packages

The server requires these packages (automatically installed by Poetry/pip):

- **httpx** (>=0.24.0) - HTTP client for HackerOne API
- **python-dotenv** (>=0.19.0) - Environment variable loading
- **pyyaml** (>=6.0) - YAML parsing for MDC files
- **mcp** (>=0.1.0) - Model Context Protocol server framework

#### Dependency Installation Troubleshooting

**1. Python Version Issues:**
```bash
# Check Python version
python --version
python3 --version

# If Python < 3.8, install newer version:
# macOS: brew install python@3.11
# Ubuntu: sudo apt install python3.11
# Windows: Download from python.org
```

**2. SSL Certificate Errors:**
```bash
# macOS SSL issues
/Applications/Python\ 3.x/Install\ Certificates.command

# Or upgrade certificates
pip install --upgrade certifi
```

**3. Compilation Errors (especially on older systems):**
```bash
# Install development tools
# Ubuntu/Debian:
sudo apt-get install build-essential python3-dev

# CentOS/RHEL:
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel

# macOS: Install Xcode command line tools
xcode-select --install
```

### 3. Set Up Environment Variables

#### Create .env File

Create a `.env` file in the project root directory:

```bash
# Navigate to project root
cd hackerone-mcp

# Create .env file
touch .env

# Edit with your preferred editor
nano .env
# or
code .env
```

Add the following content:

```bash
# HackerOne API credentials
H1_USERNAME=your_hackerone_username
H1_API_TOKEN=your_hackerone_api_token
H1_PROGRAM=your_program_handle

# Optional: Custom MDC file path
# MDC_FILE_PATH=/custom/path/to/your/mdc/file.mdc
```

**Getting HackerOne API Credentials:**

1. **Log into HackerOne**: Go to [hackerone.com](https://hackerone.com) and sign in
2. **Navigate to Settings**: Click your profile → Settings
3. **API Tokens Section**: Go to "API Tokens" tab
4. **Create Token**: Click "Create API Token"
5. **Copy Credentials**: 
   - Username: Your HackerOne username (not email)
   - API Token: The generated token (starts with `h1_`)
6. **Find Program Handle**: Your program handle is in the URL: `https://hackerone.com/your_program_handle`

**⚠️ Environment Variable Gotchas:**

- **No Quotes**: Don't wrap values in quotes in .env file
- **No Spaces**: `H1_USERNAME=value` not `H1_USERNAME = value`
- **File Location**: `.env` must be in the project root directory
- **Git Ignore**: Never commit `.env` to version control (already in .gitignore)

#### Alternative: System Environment Variables

Instead of `.env` file, you can set system environment variables:

```bash
# macOS/Linux (add to ~/.bashrc or ~/.zshrc)
export H1_USERNAME="your_username"
export H1_API_TOKEN="your_token"
export H1_PROGRAM="your_program"

# Windows (Command Prompt)
setx H1_USERNAME "your_username"
setx H1_API_TOKEN "your_token"
setx H1_PROGRAM "your_program"

# Windows (PowerShell)
$env:H1_USERNAME="your_username"
$env:H1_API_TOKEN="your_token"
$env:H1_PROGRAM="your_program"
```

### 4. Configure MDC Directives

The server includes security compliance directives through a Management Directive Compliance (MDC) file.

#### Setting Up Your MDC File

1. **Locate MDC File**: The placeholder is at `rules/hackerone_mcp_directives.mdc`
2. **⚠️ CRITICAL**: Update the hardcoded path in `src/hackerone_mcp/main.py`:

The MDC file path is now automatically configured to use dynamic paths relative to the project root. The current implementation:

```python
# Dynamic MDC file path - relative to project root
def get_project_root() -> Path:
    """Get the project root directory"""
    return Path(__file__).parent.parent.parent

# MDC file path - can be overridden with environment variable
MDC_FILE_PATH = os.getenv("MDC_FILE_PATH", str(get_project_root() / "rules" / "hackerone_mcp_directives.mdc"))
```

This automatically finds the project root and locates the MDC file, while still allowing customization via the `MDC_FILE_PATH` environment variable.

4. **Verify MDC File Exists**:

```bash
# Check if MDC file exists
ls -la rules/hackerone_mcp_directives.mdc

# If missing, create placeholder
mkdir -p rules
touch rules/hackerone_mcp_directives.mdc
```

### 5. Test Installation

#### Basic Functionality Test

```bash
# Using Poetry
poetry run python src/hackerone_mcp/main.py --help

# Using pip/venv
python src/hackerone_mcp/main.py --help
```

#### Environment Test

Create a test script `test_setup.py`:

```python
import os
from dotenv import load_dotenv
import httpx
import yaml

# Test environment loading
load_dotenv()
print("✓ Environment variables loaded")

# Test credentials
username = os.getenv("H1_USERNAME")
token = os.getenv("H1_API_TOKEN")
program = os.getenv("H1_PROGRAM")

if not all([username, token, program]):
    print("❌ Missing credentials")
    exit(1)
print("✓ Credentials configured")

# Test network connectivity
try:
    response = httpx.get("https://api.hackerone.com/v1/me", timeout=10)
    print("✓ HackerOne API accessible")
except Exception as e:
    print(f"❌ Network issue: {e}")

print("✅ Setup verification complete!")
```

Run the test:

```bash
# Using Poetry
poetry run python test_setup.py

# Using pip/venv
python test_setup.py
```

### Common Installation Issues & Solutions

#### 1. **MDC File Path Error**
```
Error: MDC file not found at /path/to/rules/hackerone_mcp_directives.mdc
```
**Solution**: 
- Ensure the MDC file exists: `ls -la rules/hackerone_mcp_directives.mdc`
- Create the directory if missing: `mkdir -p rules`
- Or set custom path via environment: `export MDC_FILE_PATH="/your/custom/path/file.mdc"`

#### 2. **Import Errors**
```
ModuleNotFoundError: No module named 'httpx'
```
**Solution**: 
- Ensure virtual environment is activated
- Reinstall dependencies: `poetry install` or `pip install -r requirements.txt`

#### 3. **Permission Denied**
```
PermissionError: [Errno 13] Permission denied
```
**Solution**:
- Check file permissions: `chmod +x src/hackerone_mcp/main.py`
- Don't run with `sudo` - use virtual environments instead

#### 4. **Python Path Issues**
```
python: command not found
```
**Solution**:
- Use `python3` instead of `python`
- Check Python installation: `which python3`
- Add Python to PATH (Windows)

#### 5. **Poetry Not Found**
```
poetry: command not found
```
**Solution**:
- Add Poetry to PATH: `export PATH="$HOME/.local/bin:$PATH"`
- Or install via pip: `pip install poetry`
- Restart terminal after installation

#### 6. **SSL/TLS Errors**
```
SSL: CERTIFICATE_VERIFY_FAILED
```
**Solution**:
- Update certificates: `pip install --upgrade certifi`
- macOS: Run `/Applications/Python\ 3.x/Install\ Certificates.command`

#### 7. **HackerOne API Authentication**
```
Error: HackerOne API returned status 401
```
**Solution**:
- Verify credentials are correct
- Check if API token has proper permissions
- Ensure program handle is exact (case-sensitive)

### 6. Test Dynamic Path Resolution

Test that the dynamic path system is working correctly:

```bash
# Run the path test script
python test_paths.py

# Expected output:
🔍 Path Resolution Test
==================================================
Current working directory: /path/to/hackerone-mcp
Test script location: /path/to/hackerone-mcp
Detected project root: /path/to/hackerone-mcp
MDC file path: /path/to/hackerone-mcp/rules/hackerone_mcp_directives.mdc
✅ MDC file found at: /path/to/hackerone-mcp/rules/hackerone_mcp_directives.mdc

🔧 Environment Variable Test
==================================================
Custom MDC path: /tmp/test_mdc.mdc

✅ Path resolution test completed successfully!
```

### 7. Verify Installation Success

If everything is working correctly, you should see:

```bash
# Run the server directly
poetry run python src/hackerone_mcp/main.py

# Expected output:
HackerOne MCP Server with MDC starting...
Server name: hackerone-mcp
Program: your_program_handle
Credentials configured: True
MDC directives loaded: True
Server running, waiting for messages...
```

Press `Ctrl+C` to stop the test.

## Connecting to Claude Desktop

### 1. Locate Claude Desktop Configuration

Find your Claude Desktop configuration file:

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

### 2. Update Configuration

Add the HackerOne MCP server to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "hackerone-mcp": {
      "command": "python",
      "args": ["/absolute/path/to/hackerone-mcp/src/hackerone_mcp/main.py"],
      "env": {
        "H1_USERNAME": "your_hackerone_username",
        "H1_API_TOKEN": "your_hackerone_api_token",
        "H1_PROGRAM": "your_program_handle"
      }
    }
  }
}
```

**Important:** Replace `/absolute/path/to/hackerone-mcp` with the full path to your project directory.

If using Poetry, use this configuration instead:

```json
{
  "mcpServers": {
    "hackerone-mcp": {
      "command": "poetry",
      "args": ["run", "python", "src/hackerone_mcp/main.py"],
      "cwd": "/absolute/path/to/hackerone-mcp",
      "env": {
        "H1_USERNAME": "your_hackerone_username",
        "H1_API_TOKEN": "your_hackerone_api_token",
        "H1_PROGRAM": "your_program_handle"
      }
    }
  }
}
```

### 3. Restart Claude Desktop

Close and restart Claude Desktop to load the new MCP server configuration.

### 4. Verify Connection

In Claude Desktop, you should see the HackerOne MCP server listed in your available tools. You can test it by asking:

> "Show me new HackerOne reports"

## Using the Server with Claude Desktop

Once connected, you can interact with your HackerOne program directly through Claude Desktop using natural language. The server provides 6 powerful tools that integrate seamlessly into your security workflow.

### Getting Started

After connecting the server, Claude Desktop will automatically have access to your HackerOne tools. You can:

- **Ask questions in natural language** - Claude will determine which tools to use
- **Request specific actions** - Directly ask for reports, analysis, or checks
- **Get guided assistance** - The MDC directives will provide security guidance automatically

### Example Conversations

Here are practical examples of how to interact with the server:

#### **Basic Report Management**

**You:** "What new vulnerability reports do I have?"

**Claude will:** Use `get_new_reports` to fetch all reports in "new" state, format them with complete details, and provide MDC triage guidance including initial questions to ask and escalation checks.

**You:** "Show me all reports for my program"

**Claude will:** Use `get_all_reports` to fetch comprehensive data on all reports regardless of state, with full metrics and status information.

#### **Detailed Report Analysis**

**You:** "Can you analyze report #1234567 for me?"

**Claude will:** Use `check_report` to get complete details including vulnerability information, timeline, reporter stats, severity assessment, and provide MDC-guided security recommendations.

**You:** "I need the full technical details for report 1234567"

**Claude will:** Fetch the complete report with both formatted summary and raw JSON data, plus security guidance on next steps.

#### **Scope and Duplicate Validation**

**You:** "Is report #1234567 within our program scope?"

**Claude will:** Use `check_scope` to compare the report against your program's structured scope, policy rules, bounty eligibility, and provide detailed scope analysis with recommendations.

**You:** "Check if report #1234567 is a duplicate"

**Claude will:** Use `check_duplicate` to perform intelligent similarity analysis across all program reports, scoring potential duplicates based on titles, weaknesses, assets, and vulnerability descriptions.

#### **Weekly Reporting and Analysis**

**You:** "Generate this week's security report"

**Claude will:** Use `make_weekly_report` to create comprehensive weekly analysis including compliance checks, metrics, trends, closed reports analysis, and actionable insights for management.

**You:** "What's our program's current status and any urgent items?"

**Claude will:** Generate weekly report focusing on immediate attention items, compliance-critical vulnerabilities, and recent activity requiring follow-up.

### Tool-Specific Usage Examples

#### 🆕 **New Reports Tool**
```
"Show me new reports that need triage"
"What new vulnerabilities came in today?"
"Are there any new reports requiring immediate escalation?"
```

**What you get:**
- Complete new reports with vulnerability details
- MDC triage questions automatically provided
- Escalation alerts for critical issues
- Researcher interaction guidelines
- Security compliance reminders

#### 📋 **All Reports Tool**
```
"Give me a complete overview of all reports"
"Show me the current state of all vulnerabilities"
"What's the full picture of our bug bounty program?"
```

**What you get:**
- Comprehensive report listing across all states
- Program performance metrics
- State distribution analysis
- Complete vulnerability timeline data

#### 🔍 **Report Details Tool**
```
"Tell me everything about report #1234567"
"I need full analysis of report 1234567"
"Show me the technical details for this specific report"
```

**What you get:**
- Complete vulnerability information and timeline
- Reporter statistics and history
- Severity assessment and methodology
- Raw JSON data for advanced analysis
- MDC security guidance and next steps

#### 🎯 **Scope Validation Tool**
```
"Is report #1234567 in scope?"
"Check if this vulnerability affects our covered assets"
"Validate the scope for report 1234567"
```

**What you get:**
- Detailed scope analysis against program policy
- Asset matching and bounty eligibility
- Maximum severity limits for the asset
- Comprehensive policy comparison
- MDC scope validation checklist

#### 🔄 **Duplicate Detection Tool**
```
"Is report #1234567 a duplicate?"
"Check for similar reports to #1234567"
"Analyze potential duplicates for this report"
```

**What you get:**
- Similarity scoring across multiple criteria
- Categorized potential duplicates (likely/possible)
- Detailed comparison reasoning
- Historical report correlation
- MDC duplicate determination guidelines

#### 📊 **Weekly Reporting Tool**
```
"Create this week's status report"
"What's our weekly security summary?"
"Generate management report for this week"
```

**What you get:**
- Comprehensive weekly activity analysis
- Compliance framework status updates
- Detailed closed reports outcomes
- Trending analysis and metrics
- Executive summary with actionable insights
- Zero-knowledge architecture integrity assessment

### Advanced Usage Tips

#### **Combining Tools for Workflow**
```
"Check report #1234567 for duplicates, scope, and give me full analysis"
```
Claude will automatically use multiple tools (`check_duplicate`, `check_scope`, `check_report`) to provide comprehensive analysis.

#### **Contextual Follow-ups**
```
You: "Show me new reports"
Claude: [Shows 5 new reports]
You: "Check if the first one is a duplicate"
```
Claude remembers context and will check the first report from the previous response.

#### **Security-Focused Queries**
```
"What reports this week need immediate security attention?"
"Are there any compliance-critical vulnerabilities I should know about?"
"Show me zero-knowledge architecture related reports"
```

The MDC framework automatically provides security-focused analysis and recommendations.

### Understanding MDC Integration

Every tool response includes:

- **🔒 Security Guidance** - Automatic policy compliance checks
- **⚠️ Escalation Alerts** - Immediate attention triggers  
- **📋 Triage Questions** - Initial assessment prompts
- **✅ Validation Checklists** - Required verification steps
- **💡 Best Practices** - Researcher interaction guidelines

### Response Formats

The server provides multiple data formats:

- **📝 Formatted Summaries** - Human-readable analysis
- **📊 Structured Data** - Organized metrics and timelines  
- **🔍 Raw JSON** - Complete API responses for advanced use
- **📈 Visual Analytics** - Trend analysis and comparisons
- **🎯 Action Items** - Specific next steps and recommendations

## Available Tools

### `get_new_reports`
Fetches all new reports (state=new) for your program with comprehensive details including reporter info, severity, and vulnerability details.

### `get_all_reports`
Fetches all reports regardless of state for comprehensive program analysis.

### `check_report`
Retrieves detailed information for a specific report by ID, including complete vulnerability information and timeline.

**Usage:** `check_report(report_id="123456")`

### `check_scope`
Analyzes whether a specific report falls within your program's scope by comparing against structured scope rules and policy.

**Usage:** `check_scope(report_id="123456")`

### `check_duplicate`
Performs intelligent duplicate analysis using similarity scoring across titles, weaknesses, assets, and vulnerability descriptions.

**Usage:** `check_duplicate(report_id="123456")`

### `make_weekly_report`
Generates comprehensive weekly status reports with metrics, trends, compliance analysis, and actionable insights.

## MDC Customization Guide

The Management Directive Compliance (MDC) file is a YAML configuration that defines your organization's security policies, triage workflows, and compliance requirements. This guide helps you customize the placeholder file for your specific needs.

### MDC File Structure

The MDC file is organized into several key sections:

```yaml
# Core organizational mission and principles
core_directives:
  primary_mission: "Your organization's security mission statement"
  
# Operational decision-making framework  
operational_principles:
  decision_framework:
    - "Evidence-based security decisions"
    - "Risk-proportionate responses"
    
# HackerOne-specific security policies
hackerone_specific_rules:
  report_triage:
    classification_questions:
      - "What is the actual security impact?"
      - "Is this reproducible in production?"
      
  researcher_interaction:
    always:
      - "Acknowledge receipt within 24 hours"
      - "Provide clear next steps"
    never:
      - "Dismiss reports without investigation"
      - "Use dismissive language"

# Compliance and validation workflows      
validation_workflows:
  before_report_closure:
    ask:
      - "Has impact been fully assessed?"
      - "Are compliance requirements met?"

# Escalation triggers and procedures
escalation_triggers:
  immediate_escalation:
    - "zero-day"
    - "data breach"
    - "authentication bypass"
  questions_during_escalation:
    - "Who needs immediate notification?"
    - "What compliance reporting is required?"

# Daily operational reminders
reminder:
  core_philosophy: "Your key security principle or reminder"
```

### Customizing Your MDC File

#### 1. **Define Your Core Mission**

Replace the placeholder mission with your organization's actual security objectives:

```yaml
core_directives:
  primary_mission: "Protect customer data through proactive vulnerability management and rapid incident response"
```

#### 2. **Set Triage Questions**

Customize questions based on your specific threat model and business context:

```yaml
hackerone_specific_rules:
  report_triage:
    classification_questions:
      - "Does this affect customer data?"
      - "Is this exploitable in our production environment?"
      - "What is the CVSS score based on our infrastructure?"
      - "Are there compensating controls in place?"
```

#### 3. **Configure Severity Rules**

Define specific validation requirements for different severity levels:

```yaml
hackerone_specific_rules:
  report_triage:
    severity_assessment:
      critical:
        ask_before_marking: "Has executive team been notified?"
        verification: "Confirmed exploitable in production"
      high:
        clarify: "Business impact assessment completed"
      medium:
        verification: "Reproducibility confirmed"
```

#### 4. **Set Researcher Interaction Policies**

Define your organization's communication standards:

```yaml
hackerone_specific_rules:
  researcher_interaction:
    always:
      - "Respond within your published SLA timeframe"
      - "Provide technical rationale for decisions"
      - "Thank researchers for their contributions"
    never:
      - "Share internal vulnerability assessment details"
      - "Make promises about fix timelines without approval"
```

#### 5. **Configure Escalation Triggers**

Set keywords and conditions that require immediate escalation:

```yaml
escalation_triggers:
  immediate_escalation:
    - "remote code execution"
    - "sql injection"
    - "authentication bypass"
    - "privilege escalation"
    - "your-critical-system-name"
  questions_during_escalation:
    - "Has the security team lead been notified?"
    - "Is this affecting production systems?"
    - "Do we need to invoke incident response procedures?"
```

#### 6. **Define Validation Workflows**

Create checklists for different operational stages:

```yaml
validation_workflows:
  before_report_closure:
    ask:
      - "Has the fix been deployed and verified?"
      - "Has the researcher been properly thanked?"
      - "Are compliance documentation requirements met?"
  
  before_bounty_award:
    ask:
      - "Is the bounty amount consistent with our policy?"
      - "Has the impact been properly validated?"
```

### Industry-Specific Customizations

#### **Financial Services**
```yaml
escalation_triggers:
  immediate_escalation:
    - "payment processing"
    - "customer financial data"
    - "regulatory compliance"
    
validation_workflows:
  before_report_closure:
    ask:
      - "Does this require regulatory notification?"
      - "Has PCI DSS impact been assessed?"
```

#### **Healthcare**
```yaml
escalation_triggers:
  immediate_escalation:
    - "patient data"
    - "hipaa"
    - "phi exposure"
    
validation_workflows:
  before_report_closure:
    ask:
      - "Has HIPAA compliance officer been notified?"
      - "Is patient data exposure documented?"
```

#### **SaaS/Technology**
```yaml
escalation_triggers:
  immediate_escalation:
    - "customer data access"
    - "multi-tenant isolation"
    - "api authentication"
    
hackerone_specific_rules:
  report_triage:
    classification_questions:
      - "Does this affect multiple customers?"
      - "Can this be exploited at scale?"
```

### Testing Your MDC Configuration

After customizing your MDC file:

1. **Validate YAML Syntax**: Use a YAML validator to ensure proper formatting
2. **Test with Sample Reports**: Run the server against test data to verify your rules work as expected  
3. **Review with Security Team**: Have your security team review the policies and escalation triggers
4. **Iterate Based on Usage**: Adjust rules based on real-world usage and feedback

### MDC Best Practices

- **Keep It Updated**: Review and update your MDC file quarterly
- **Version Control**: Track changes to your MDC file in version control
- **Document Changes**: Maintain a changelog for MDC policy updates
- **Team Training**: Ensure your team understands the policies defined in the MDC
- **Regular Audits**: Periodically audit whether your actual practices match your MDC policies

## MDC Security Directives

The server includes built-in security compliance features:

- **Triage Guidance**: Automated prompts for essential security questions
- **Escalation Detection**: Automatic identification of reports requiring immediate attention
- **Researcher Interaction Guidelines**: Best practices for professional communication
- **Compliance Checks**: Built-in validation against security frameworks

## Troubleshooting

### Common Issues

**1. "Credentials not configured" error**
- Verify your `.env` file contains correct HackerOne credentials
- Ensure environment variables are properly set in Claude Desktop configuration

**2. "Program not found" error**
- Check that your `H1_PROGRAM` value matches your actual program handle
- Verify you have access to the specified program in HackerOne

**3. "Connection timeout" errors**
- Check your internet connection
- Verify HackerOne API is accessible from your network
- Consider increasing timeout values if on a slow connection

**4. Claude Desktop doesn't show the server**
- Verify the absolute path in your configuration is correct
- Check that Python/Poetry is available in your system PATH
- Review Claude Desktop logs for error messages

### Debug Mode

To enable debug logging, run the server directly:

```bash
# Using Poetry
poetry run python src/hackerone_mcp/main.py

# Using Python directly
python src/hackerone_mcp/main.py
```

This will show detailed logging information to help diagnose issues.

### Logs Location

Claude Desktop logs can be found at:
- **macOS:** `~/Library/Logs/Claude/`
- **Windows:** `%APPDATA%\Claude\logs\`
- **Linux:** `~/.config/Claude/logs/`

## Security Considerations

- Store API credentials securely and never commit them to version control
- Use environment variables or secure credential management systems
- Regularly rotate your HackerOne API tokens
- Monitor API usage to detect any unauthorized access
- Follow your organization's security policies for API integrations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues related to:
- **HackerOne API**: Check HackerOne's API documentation and support
- **Claude Desktop**: Refer to Anthropic's Claude Desktop documentation
- **This MCP Server**: Open an issue in this repository

## Changelog

### v1.0.0
- Initial release with core HackerOne integration
- MDC compliance framework integration
- Full report management capabilities
- Claude Desktop MCP integration
