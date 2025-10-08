import pandas as pd
import subprocess
import json
import sys
from collections import defaultdict

# --- Configuration ---
# Name of the column containing user and service account emails
PRINCIPAL_COLUMN_NAME = "Email" 
# Name of the mapping file
ROLE_MAPPING_FILE = "role_mapping.json"

# List of substrings to identify and ignore Google-managed service agents
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
        # Read the first three rows as headers to handle the multi-level structure
        df = pd.read_excel(filepath, header=[0, 1, 2])
        # Reset the index to work with the data, then drop the original multi-level columns
        df_reset = df.reset_index()
        df_reset.columns = [' '.join(map(str, col)).strip() for col in df_reset.columns.values]
    except FileNotFoundError:
        print(f"❌ Error: The file '{filepath}' was not found.")
        sys.exit(1)
    
    # Identify the actual project columns by looking for headers that are not standard info columns
    info_cols = ['Email Unit Kerja Status', 'Email Unit Kerja Date Updated', 'Email Access Type Unnamed: 4_level_2']
    project_cols = [col for col in df_reset.columns if col not in info_cols and not col.startswith('Email')]
    
    # Get the unique project IDs from the first level of the original columns
    project_ids = sorted(list(set([col[0] for col in df.columns if '-' in col[0]])))
    
    desired_state = defaultdict(lambda: defaultdict(set))
    
    for _, row in df_reset.iterrows():
        principal_email = row.get('Email Unit Kerja Status')
        if not principal_email or pd.isna(principal_email):
            continue

        prefix = "serviceAccount:" if principal_email.endswith(".gserviceaccount.com") else "user:"
        full_principal_name = f"{prefix}{principal_email}"

        for proj_col_name in project_cols:
            if row[proj_col_name] == True:
                # Extract project ID and permission name from the column header
                project_id = proj_col_name.split(' ')[0]
                permission_name = proj_col_name.split(' ')[-1]

                # Find the corresponding roles from the mapping
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
            is_google_managed = False
            if member.startswith("serviceAccount:"):
                for pattern in GOOGLE_MANAGED_PATTERNS:
                    if pattern in member:
                        is_google_managed = True; break
            if not is_google_managed:
                actual_state[member].add(binding["role"])
    
    return actual_state

def main():
    """Main function to orchestrate the multi-project IAM audit."""
    filepath = input("Enter the path to your IAM matrix Excel file (e.g., 'user_list_access.xlsx'): ")
    
    role_mapping = load_role_mapping()
    desired_state, project_ids = load_and_parse_spreadsheet(filepath, role_mapping)
    
    print("\n" + "="*50)
    print("        🚀 Starting Advanced Multi-Project IAM Audit 🚀")
    print("="*50)

    for project_id in project_ids:
        actual_state = get_project_iam_state(project_id)
        if actual_state is None: continue

        desired_principals = set(desired_state.get(project_id, {}).keys())
        actual_principals = set(actual_state.keys())

        unauthorized = actual_principals - desired_principals
        missing = desired_principals - actual_principals
        common = actual_principals.intersection(desired_principals)
        
        has_findings = False
        if unauthorized:
            has_findings = True
            print("  🚨 UNAUTHORIZED PRINCIPALS (in GCP but not spreadsheet):")
            for p in sorted(unauthorized): print(f"     - {p} has roles: {sorted(list(actual_state[p]))}")

        if missing:
            has_findings = True
            print("  ⚠️  MISSING PRINCIPALS (in spreadsheet but not in GCP):")
            for p in sorted(missing): print(f"     - {p}")

        print("  🔎 Checking for role mismatches...")
        for p in sorted(common):
            desired_roles = desired_state[project_id][p]
            actual_roles = actual_state[p]
            
            extra = actual_roles - desired_roles
            missing = desired_roles - actual_roles

            if extra: has_findings = True; print(f"     - 🚨 EXTRA ROLES for {p}: {sorted(list(extra))}")
            if missing: has_findings = True; print(f"     - ⚠️  MISSING ROLES for {p}: {sorted(list(missing))}")

        if not has_findings: print("  ✅ No discrepancies found.")

    print("\n" + "="*50 + "\n          ✨ Audit Complete ✨\n" + "="*50)

if __name__ == "__main__":
    main()