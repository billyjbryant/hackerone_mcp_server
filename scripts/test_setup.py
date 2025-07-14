import os
from dotenv import load_dotenv
import httpx
import base64

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

print(f"  - username: {username}")
print(f"  - token: {token[:5] if token else 'None'}...")
print(f"  - program: {program}")

# Test network connectivity
try:
    response = httpx.get("https://api.hackerone.com/v1/me", timeout=10)
    print("✓ HackerOne API reachable")
except Exception as e:
    print(f"❌ Network issue: {e}")
    exit(1)

auth = base64.b64encode(f"{username}:{token}".encode()).decode()
headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}


# Test program access authorization
print("\n--- Testing Authentication Access ---")
program_id = None
program_name = None

try:
    # Step 1: Get all accessible programs
    response = httpx.get(
        "https://api.hackerone.com/v1/me/programs",
        headers=headers,
        params={"filter[state][]": "active"},
        timeout=10,
    )

    if response.status_code == 200:
        programs_data = response.json()
        print("✓ Authentication successful")
        active_programs = programs_data.get("data", [])
        print(f"  Active programs accessible: {len(active_programs)}")

        # Debug: Show structure of first program
        if active_programs:
            first_program = active_programs[0]
            if "attributes" in first_program:
                attrs = first_program["attributes"]

        # Step 2: Find the specific program by handle
        target_program = None
        for prog in active_programs:
            prog_attrs = prog.get("attributes", {})
            prog_handle = prog_attrs.get("handle", "Unknown")
            if prog_handle == program:
                target_program = prog
                break

        if target_program:
            program_id = target_program.get("id", "Unknown")
            prog_attrs = target_program.get("attributes", {})
            program_name = prog_attrs.get("handle", "Unknown")

            print(f"✓ Found target program: {program_name}")
            print(f"  ID: {program_id}")
        else:
            print(f"❌ Program '{program}' not found in accessible programs")
            print("  Available programs:")
            for prog in active_programs[:5]:  # Show first 5
                prog_attrs = prog.get("attributes", {})
                handle = prog_attrs.get("handle", "Unknown")
                prog_id = prog_attrs.get("id", "Unknown")
                print(f"    - {handle} (ID: {prog_id})")
            exit(1)

    elif response.status_code == 401:
        print("❌ Authentication failed - Invalid credentials")
        exit(1)
    else:
        status_code = response.status_code
        print(f"❌ Programs access test failed with status {status_code}")
        print(f"Response: {response.text}")
        exit(1)

except Exception as e:
    print(f"❌ Program access test error: {e}")
    exit(1)

# Test program access authorization
print("\n--- Testing Program Access ---")
try:
    # Test access to specific program
    program_url = f"https://api.hackerone.com/v1/programs/{program_id}"
    response = httpx.get(program_url, headers=headers, timeout=10)

    if response.status_code == 200:
        program_data = response.json()
        print("✓ Program access authorized")
        print(f"  Handle: {program_data['data']['attributes']['handle']}")
        print(f"  ID: {program_data['data']['id']}")
    elif response.status_code == 404:
        print(f"❌ Program '{program}' not found or no access")
        exit(1)
    elif response.status_code == 403:
        print(f"❌ Access denied to program '{program}'")
        exit(1)
    else:
        status_code = response.status_code
        print(f"❌ Program access test failed with status {status_code}")
        print(f"Response: {response.text}")
        exit(1)

except Exception as e:
    print(f"❌ Program access test error: {e}")
    exit(1)

# Test reports access (basic read permission)
print("\n--- Testing Reports Access ---")
try:
    # Test ability to read reports from the program using program ID
    response = httpx.get(
        "https://api.hackerone.com/v1/reports",
        headers=headers,
        params={"filter[program][]": program, "page[size]": 1},
        timeout=10,
    )

    if response.status_code == 200:
        reports_data = response.json()
        print("✓ Reports access authorized")
        print(f"  Can access reports for program: {program_name}")
    elif response.status_code == 403:
        print(f"❌ Access denied to reports for program '{program_name}'")
        exit(1)
    else:
        status_code = response.status_code
        print(f"❌ Reports access test failed with status {status_code}")
        print(f"Response: {response.text}")
        exit(1)

except Exception as e:
    print(f"❌ Reports access test error: {e}")
    exit(1)

print("\n✅ All authentication and authorization tests passed!")
