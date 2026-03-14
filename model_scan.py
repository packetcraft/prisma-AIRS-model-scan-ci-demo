import os
import sys
import argparse
import json
import pprint
from model_security_client.api import ModelSecurityAPIClient

def parse_arguments():
    """Parses command-line arguments for model path and security group ID."""
    parser = argparse.ArgumentParser(description="Prisma AIRS Model Security Scan")
    
    parser.add_argument(
        "--model-path",
        required=True,
        help="Path to the model artifact (local path) or URL (Hugging Face)."
    )
    
    parser.add_argument(
        "--security-group-id",
        required=True,
        help="The UUID of the security group."
    )
    
    return parser.parse_args()

def run_model_scan(model_path: str, security_group_id: str):
    """
     Initializes the Client, scans the model, and enforces the security policy.
    """
    try:
        # 1. Initialize the Client
        # We use the environment variable for the endpoint, defaulting to the prod URL
        base_url = os.getenv("MODEL_SECURITY_API_ENDPOINT", "https://api.sase.paloaltonetworks.com/aims")
        
        print(f"🚀 Initializing Client connecting to: {base_url}")
        client = ModelSecurityAPIClient(base_url=base_url)

        # 2. Determine URI Type (Local File vs. Hugging Face URL)
        if model_path.startswith("http://") or model_path.startswith("https://"):
            final_model_uri = model_path
            print(f"   Target: Remote URL ({model_path})")
        else:
            abs_path = os.path.abspath(model_path)
            final_model_uri = f"file://{abs_path}"
            print(f"   Target: Local File ({abs_path})")

        print(f"   Profile UUID: {security_group_id}")

        # 3. Perform the scan
        result = client.scan(
            security_group_uuid=security_group_id,
            model_uri=final_model_uri
        )

        # 4. Process Results
        print(f"\n🏁 Scan Status: {result.eval_outcome}")
        
        # Convert result to dictionary safely
        try:
            data_dict = result.model_dump()
        except AttributeError:
            data_dict = result.__dict__

        # Save report for GitHub Artifacts
        with open('model_scan_report.json', 'w') as f:
            json.dump(data_dict, f, indent=4, default=str)
        print("   Report saved to 'model_scan_report.json'")

        # 5. POLICY ENFORCEMENT (The Gatekeeper)
        policy_violated = False
        
        # Check 1: High level outcome (FIXED LOGIC)
        outcome_str = str(result.eval_outcome).upper()
        
        # If the result is NOT strictly 'PASS' or 'CLEAN', we trigger a violation.
        # This catches 'BLOCKED', 'WARNING', 'FAILURE', etc.
        if outcome_str not in ["PASS", "CLEAN", "SUCCESS"]:
            print(f"⚠️  VIOLATION: Outcome was '{outcome_str}' (Expected: PASS)")
            policy_violated = True 
            
        # Check 2: Deep dive into findings (Double check for critical issues)
        findings = data_dict.get("findings", [])
        if findings:
            print("\n🔍 Detailed Findings:")
            for finding in findings:
                severity = str(finding.get('severity', 'UNKNOWN')).upper()
                category = finding.get('category', 'Generic')
                print(f"   - [{severity}] {category}")
                
                # Optional: Fail specifically on High/Critical even if outcome said PASS (Defense in depth)
                if severity in ['CRITICAL', 'HIGH']:
                    policy_violated = True

        # 6. Exit Code Determination
        if policy_violated:
            print("\n⛔ FAIL: Security violations detected. Stopping pipeline.")
            sys.exit(1) # <--- This makes the GitHub Action turn RED
        else:
            print("\n✅ PASS: Model is secure.")
            sys.exit(0) # <--- This makes the GitHub Action turn GREEN

    except Exception as e:
        print(f"\n💥 CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    args = parse_arguments()
    run_model_scan(args.model_path, args.security_group_id)
