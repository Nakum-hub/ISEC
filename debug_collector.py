import os
import traceback
from src.core.collector import EvidenceCollector

if __name__ == "__main__":
    print("Starting debug...")
    # Use absolute path for robustness
    output_dir = os.path.join(os.getcwd(), 'evidence_output')
    os.makedirs(output_dir, exist_ok=True)

    try:
        collector = EvidenceCollector(output_dir)
        # Verify role manager access
        current_role = collector.role_manager.get_current_role()
        # Cleanly print the role value if possible, or the enum
        if hasattr(current_role, 'value'):
            role_str = current_role.value
        else:
            role_str = str(current_role)
        print(f"Role: {role_str}")

        has_permission = collector.role_manager.has_permission('collect')
        print(f"Permission to collect: {has_permission}")

        if has_permission:
            collector.collect_all_evidence()
            print("Evidence collection completed.")
        else:
            print("Skipping collection due to lack of permissions.")

        print("Debug finished success.")

    except Exception as e:
        print(f"Debug failed: {e}")
        traceback.print_exc()
