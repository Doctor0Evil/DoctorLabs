#!/bin/bash
# Red-teaming script for AI-chat account capture scenarios

RED_TEAM_ACTORS=("LEO_Actor_1" "Safety_Team_Actor" "Fake_Welfare_Check")
LOG_FILE="/var/log/cyb_ai/red_teaming_results.log"

for actor in "${RED_TEAM_ACTORS[@]}"; do
  echo "[+] Testing $actor..."
  python3 /cyb.ai/tests/attack_simulator.py --actor "$actor" --action "reset_credentials"
  python3 /cyb.ai/tests/attack_simulator.py --actor "$actor" --action "read_logs"
  python3 /cyb.ai/tests/attack_simulator.py --actor "$actor" --action "throttle_capabilities"
  echo "[-] Completed $actor tests. Check $LOG_FILE for results."
done

# Regression test: Ensure no path reduces user capabilities
python3 /cyb.ai/tests/monotonicity_test.py
