import pandas as pd
import subprocess
import json
import sys
import os
from collections import defaultdict
from tabulate import tabulate

# --- Configuration ---
PRINCIPAL_COLUMN_NAME = "Email"
ROLE_MAPPING_FILE = "role_mapping.json"
OUTPUT_DIRECTORY = "iam_audit_reports"

# List of substrings to identify and ignore ALL service accounts
GOOGLE_MANAGED_PATTERNS = [
    ".iam.gserviceaccount.com",
]

def run_gcloud_command(command):
    """Runs a gcloud command and returns the output or an error string."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"GCLOUD_ERROR: {e.stderr.strip()}"

def load_role_mapping():
    """Loads the permission-to-role mapping from the JSON file."""
    try:
        with open(ROLE_MAPPING_FILE, 'r', encoding="utf-8") as f: # Added encoding for safety
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Critical Error: The mapping file '{ROLE_MAPPING_FILE}' was not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"❌ Critical Error: The mapping file '{ROLE_MAPPING_FILE}' is not a valid JSON file.")
        sys.exit(1)

def load_and_parse_spreadsheet(filepath, role_mapping):
    """Loads the complex Excel matrix and builds the desired IAM state."""
    print(f"📖 Reading IAM matrix from '{filepath}'...")
    try:
        df = pd.read_excel(filepath, header=[0, 1, 2])
        df_reset = df.reset_index(drop=True)
        df_reset.columns = [' '.join(map(str, col)).strip() for col in df.columns.values]
    except FileNotFoundError:
        print(f"❌ Error: The file '{filepath}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An error occurred while reading the Excel file: {e}")
        sys.exit(1)

    try:
        email_column_name = next(col for col in df_reset.columns if col.startswith(PRINCIPAL_COLUMN_NAME))
    except StopIteration:
        print(f"❌ Critical Error: Could not find a column starting with '{PRINCIPAL_COLUMN_NAME}' in the spreadsheet.")
        sys.exit(1)
    
    project_cols = [col for col in df_reset.columns if not col.startswith(PRINCIPAL_COLUMN_NAME)]
    project_ids = sorted(list(set([col[0] for col in df.columns if isinstance(col[0], str) and '-' in col[0]])))
    
    desired_state = defaultdict(lambda: defaultdict(set))
    
    for _, row in df_reset.iterrows():
        principal_email = row.get(email_column_name)
        if not isinstance(principal_email, str) or '@' not in principal_email:
            continue

        prefix = "serviceAccount:" if principal_email.endswith(".gserviceaccount.com") else "user:"
        full_principal_name = f"{prefix}{principal_email}"

        for proj_col_name in project_cols:
            if str(row.get(proj_col_name, '')).upper() == 'TRUE':
                project_id_parts = [part for part in proj_col_name.split() if '-' in part]
                if not project_id_parts: continue
                project_id = project_id_parts[0]
                permission_name = proj_col_name.split()[-1]
                roles_to_add = role_mapping.get(permission_name, role_mapping.get("default_vm_access", []))
                for role in roles_to_add:
                    desired_state[project_id][full_principal_name].add(role)

    print(f"✅ Parsed spreadsheet. Found {len(project_ids)} projects to audit.")
    return desired_state, project_ids

def get_project_iam_state(project_id):
    """Fetches and parses the IAM policy for a single project."""
    print(f"\n- - - Auditing Project: {project_id} - - -")
    print("  Fetching current IAM policy from GCP...")
    command = f'gcloud projects get-iam-policy "{project_id}" --format="json"'
    iam_policy_json = run_gcloud_command(command)
    
    if "GCLOUD_ERROR" in iam_policy_json:
        print(f"  ❌ Failed to fetch IAM policy: {iam_policy_json}")
        return None

    actual_state = defaultdict(set)
    for binding in json.loads(iam_policy_json).get("bindings", []):
        for member in binding.get("members", []):
            if not any(pattern in member for pattern in GOOGLE_MANAGED_PATTERNS):
                actual_state[member].add(binding["role"])
    
    return actual_state

def main():
    """Main function to orchestrate the multi-project IAM audit."""
    filepath = input("Enter the path to your IAM matrix Excel file (e.g., 'access_user_djbk.xlsx'): ")
    
    role_mapping = load_role_mapping()
    desired_state, project_ids = load_and_parse_spreadsheet(filepath, role_mapping)
    
    if not os.path.exists(OUTPUT_DIRECTORY):
        os.makedirs(OUTPUT_DIRECTORY)
        print(f"📁 Created directory for reports: '{OUTPUT_DIRECTORY}'")

    print("\n" + "="*60)
    print("        🚀 Starting Advanced Multi-Project IAM Audit 🚀")
    print("="*60)

    for project_id in project_ids:
        actual_state = get_project_iam_state(project_id)
        
        report_lines = []
        report_lines.append(f"IAM AUDIT REPORT FOR PROJECT: {project_id}")
        report_lines.append("="*60)

        if actual_state is None:
            report_lines.append("\n  ❌ Failed to fetch IAM policy from GCP. Cannot generate report.")
        else:
            desired_principals = set(desired_state.get(project_id, {}).keys())
            actual_principals = set(actual_state.keys())

            unauthorized = sorted(list(actual_principals - desired_principals))
            missing = sorted(list(desired_principals - actual_principals))
            common = sorted(list(actual_principals.intersection(desired_principals)))
            
            unauthorized_table = [[p, "\n".join(sorted(list(actual_state[p])))] for p in unauthorized]
            mismatch_table = []
            for p in common:
                desired_roles = desired_state[project_id][p]
                actual_roles = actual_state[p]
                extra = actual_roles - desired_roles
                missing_roles = desired_roles - actual_roles
                if extra: mismatch_table.append([p, "🚨 Extra Roles", "\n".join(sorted(list(extra)))])
                if missing_roles: mismatch_table.append([p, "⚠️  Missing Roles", "\n".join(sorted(list(missing_roles)))])

            if not (unauthorized_table or mismatch_table or missing):
                report_lines.append("\n  ✅ No discrepancies found.")
            else:
                if unauthorized_table:
                    report_lines.append("\n\n  🚨 UNAUTHORIZED PRINCIPALS (in GCP but not spreadsheet):")
                    report_lines.append(tabulate(unauthorized_table, headers=["Principal", "Roles Found"], tablefmt="grid"))
                if mismatch_table:
                    report_lines.append("\n\n  🔎 ROLE MISMATCHES (for principals in both GCP and spreadsheet):")
                    report_lines.append(tabulate(mismatch_table, headers=["Principal", "Finding", "Roles"], tablefmt="grid"))
                if missing:
                    report_lines.append("\n\n  ⚠️  MISSING PRINCIPALS (in spreadsheet but not in GCP):")
                    for p in missing: report_lines.append(f"     - {p}")
        
        report_content = "\n".join(report_lines)
        output_filename = os.path.join(OUTPUT_DIRECTORY, f"{project_id}_iam_audit.txt")
        
        # --- THE FIX IS HERE ---
        # Explicitly open the file with UTF-8 encoding to support all characters.
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        
        print(f"  📄 Report saved to: '{output_filename}'")

    print("\n" + "="*60 + "\n          ✨ Audit Complete ✨\n" + "="*60)

if __name__ == "__main__":
    main()