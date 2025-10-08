import pandas as pd
import subprocess
import json
import sys
from collections import defaultdict
from tabulate import tabulate # Import the new library

# --- Configuration ---
# Name of the column containing user and service account emails
PRINCIPAL_COLUMN_NAME = "Email" 
# Name of the mapping file
ROLE_MAPPING_FILE = "role_mapping.json"

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
        with open(ROLE_MAPPING_FILE, 'r') as f:
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
        df_reset = df.reset_index()
        df_reset.columns = [' '.join(map(str, col)).strip() for col in df_reset.columns.values]
    except FileNotFoundError:
        print(f"❌ Error: The file '{filepath}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An error occurred while reading the Excel file: {e}")
        sys.exit(1)
    
    info_cols = [col for col in df_reset.columns if col.startswith('Email') or col.startswith('index')]
    project_cols = [col for col in df_reset.columns if col not in info_cols]
    project_ids = sorted(list(set([col[0] for col in df.columns if isinstance(col[0], str) and '-' in col[0]])))
    
    desired_state = defaultdict(lambda: defaultdict(set))
    
    for _, row in df_reset.iterrows():
        principal_email = row.get(info_cols[0])
        if not principal_email or pd.isna(principal_email): continue

        prefix = "serviceAccount:" if principal_email.endswith(".gserviceaccount.com") else "user:"
        full_principal_name = f"{prefix}{principal_email}"

        for proj_col_name in project_cols:
            if row[proj_col_name] == True:
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
            is_filtered_out = False
            # Check if the member matches any of the exclusion patterns
            for pattern in GOOGLE_MANAGED_PATTERNS:
                if pattern in member:
                    is_filtered_out = True
                    break
            if not is_filtered_out:
                actual_state[member].add(binding["role"])
    
    return actual_state

def main():
    """Main function to orchestrate the multi-project IAM audit."""
    filepath = input("Enter the path to your IAM matrix Excel file (e.g., user_list.xlsx'): ")
    
    role_mapping = load_role_mapping()
    desired_state, project_ids = load_and_parse_spreadsheet(filepath, role_mapping)
    
    print("\n" + "="*60)
    print("        🚀 Starting Advanced Multi-Project IAM Audit 🚀")
    print("="*60)

    for project_id in project_ids:
        actual_state = get_project_iam_state(project_id)
        if actual_state is None: continue

        desired_principals = set(desired_state.get(project_id, {}).keys())
        actual_principals = set(actual_state.keys())

        unauthorized = sorted(list(actual_principals - desired_principals))
        missing = sorted(list(desired_principals - actual_principals))
        common = sorted(list(actual_principals.intersection(desired_principals)))
        
        # --- Data Collection for Tables ---
        unauthorized_table = []
        mismatch_table = []
        
        for p in unauthorized:
            unauthorized_table.append([p, "\n".join(sorted(list(actual_state[p])))])
        
        for p in common:
            desired_roles = desired_state[project_id][p]
            actual_roles = actual_state[p]
            extra = actual_roles - desired_roles
            missing_roles = desired_roles - actual_roles
            if extra:
                mismatch_table.append([p, "🚨 Extra Roles", "\n".join(sorted(list(extra)))])
            if missing_roles:
                mismatch_table.append([p, "⚠️  Missing Roles", "\n".join(sorted(list(missing_roles)))])

        # --- Report Generation ---
        has_findings = unauthorized_table or mismatch_table or missing
        
        if not has_findings:
            print("  ✅ No discrepancies found.")
            continue

        if unauthorized_table:
            print("\n  🚨 UNAUTHORIZED PRINCIPALS (in GCP but not spreadsheet):")
            print(tabulate(unauthorized_table, headers=["Principal", "Roles Found"], tablefmt="grid"))

        if mismatch_table:
            print("\n  🔎 ROLE MISMATCHES (for principals in both GCP and spreadsheet):")
            print(tabulate(mismatch_table, headers=["Principal", "Finding", "Roles"], tablefmt="grid"))
            
        if missing:
            print("\n  ⚠️  MISSING PRINCIPALS (in spreadsheet but not in GCP):")
            # For simple lists, just print them out.
            for p in missing:
                print(f"     - {p}")

    print("\n" + "="*60 + "\n          ✨ Audit Complete ✨\n" + "="*60)

if __name__ == "__main__":
    main()