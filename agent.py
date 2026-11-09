import csv
import json
import warnings
from typing import List, Optional, TypedDict

# Suppress LangChain pending deprecation warnings cleanly
from langchain_core._api import LangChainDeprecationWarning

warnings.simplefilter("ignore", category=LangChainDeprecationWarning)

from langgraph.graph import END, StateGraph


# ==========================================
# PART 1: Define the State (TODO 1)
# ==========================================
class AlertState(TypedDict):
  alert_id: str
  alert_text: str
  source_type: str
  keywords_found: List[str]
  enrichment_data: Optional[dict]
  decision: str  # "escalate" or "close"


# ==========================================
# PART 1: Nodes & Tools (TODO 2 & TODO 4)
# ==========================================
def extract_keywords_node(state: AlertState) -> dict:
  """TODO 2: A node that checks alert text for suspicious keywords."""
  text = state["alert_text"].lower()
  # Baseline keyword list (expand this to tune your false positive/negative trade-off)
  suspicious_words = [
      "mimikatz",
      "powershell -enc",
      "unusual login",
      "root",
      "c2",
      "malware",
      "exfiltration",
      "suspicious",
  ]
  found = [word for word in suspicious_words if word in text]
  return {"keywords_found": found}


def mock_asset_lookup(ip_or_asset: str) -> dict:
  """TODO 4: An ordinary Python function acting as an asset/reputation tool."""
  critical_assets = ["srv-dc-01", "finance-db", "10.0.1.5", "admin"]
  is_critical = any(asset in ip_or_asset.lower() for asset in critical_assets)
  return {
      "criticality": "high" if is_critical else "normal",
      "known_host": True,
  }


def tool_node(state: AlertState) -> dict:
  """TODO 4: Node that calls the tool and updates enrichment data."""
  enrichment = mock_asset_lookup(state["alert_text"])
  return {"enrichment_data": enrichment}


def close_node(state: AlertState) -> dict:
  return {"decision": "close"}


def escalate_node(state: AlertState) -> dict:
  return {"decision": "escalate"}


# ==========================================
# PART 1: The Router (TODO 3)
# ==========================================
def route_alert(state: AlertState) -> str:
  """TODO 3: Returns the label of the next branch based on state."""
  if state["keywords_found"]:
    return "call_tool"  # Send through tool/enrichment branch
  else:
    return "close_alert"  # Close immediately if no keywords match


# ==========================================
# PART 1: Build and Compile Graph (TODO 5)
# ==========================================
def build_triage_graph():
  workflow = StateGraph(AlertState)

  # Add nodes
  workflow.add_node("extract", extract_keywords_node)
  workflow.add_node("enrich", tool_node)
  workflow.add_node("close", close_node)
  workflow.add_node("escalate", escalate_node)

  # Set entry point
  workflow.set_entry_point("extract")

  # Add conditional routing edge from extract node
  workflow.add_conditional_edges(
      "extract",
      route_alert,
      {
          "call_tool": "enrich",
          "close_alert": "close",
      },
  )

  # Add edge from enrich node to final escalation decision
  workflow.add_edge("enrich", "escalate")

  # Terminal edges
  workflow.add_edge("close", END)
  workflow.add_edge("escalate", END)

  return workflow.compile()


# ==========================================
# PARTS 2 & 3: Evaluation Runner & CSV Export
# ==========================================
def run_evaluation():
  app = build_triage_graph()

  try:
    with open("my_alerts.json", "r", encoding="utf-8") as f:
      alerts = json.load(f)
  except FileNotFoundError:
    print(
        "Error: 'my_alerts.json' not found. Please create it with your 12"
        " labelled alerts."
    )
    return
  except json.JSONDecodeError as e:
    print(f"Error: 'my_alerts.json' contains invalid JSON formatting: {e}")
    return

  results = []
  summary = {"caught": 0, "missed": 0, "over_escalated": 0, "correct_close": 0}

  for alert in alerts:
    initial_state = {
        "alert_id": alert.get("id", "unknown"),
        "alert_text": alert.get("text", ""),
        "source_type": alert.get("source", "unknown"),
        "keywords_found": [],
        "enrichment_data": None,
        "decision": "",
    }

    # Run the graph on the alert
    final_state = app.invoke(initial_state)
    predicted = final_state["decision"]
    actual = alert.get("label")

    # Measure the outcomes
    if actual == "escalate" and predicted == "escalate":
      outcome = "caught"
    elif actual == "escalate" and predicted == "close":
      outcome = "missed"
    elif actual == "close" and predicted == "escalate":
      outcome = "over_escalated"
    else:
      outcome = "correct_close"

    summary[outcome] += 1

    results.append({
        "alert_id": alert.get("id"),
        "actual": actual,
        "predicted": predicted,
        "outcome": outcome,
    })

  # Save results to results_mine.csv
  csv_filename = "results_mine.csv"
  with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = ["alert_id", "actual", "predicted", "outcome"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
      writer.writerow(r)

  print(
      f"Evaluation complete! Processed {len(results)} alerts. Results saved to"
      f" {csv_filename}."
  )
  print("\n--- Error Measurement Summary ---")
  print(f"Total Alerts Processed: {len(results)}")
  print(f"Caught (True Positives): {summary['caught']}")
  print(f"Missed Incidents (False Negatives): {summary['missed']}")
  print(f"Over Escalated Noise (False Positives): {summary['over_escalated']}")
  print(f"Correct Closes (True Negatives): {summary['correct_close']}")


if __name__ == "__main__":
  run_evaluation()