#!/usr/bin/env python3
"""Test script to verify auto-trigger logic with CVE query"""

import asyncio
import websockets
import json
import sys
import os

# Set UTF-8 encoding for stdout
os.environ['PYTHONIOENCODING'] = 'utf-8'

async def test_cve_query():
    """Test the agent with a CVE vulnerability query"""
    uri = "ws://localhost:8002/ws/chat"

    try:
        async with websockets.connect(uri) as websocket:
            # Send a CVE query
            test_message = "Phan tich CVE-2024-38213"
            print(f"[SEND] Testing query: {test_message}\n")

            await websocket.send(json.dumps({"message": test_message}))

            # Receive responses
            print("[RECV] Waiting for agent responses:")
            response_count = 0
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                    response = json.loads(message)

                    # Display based on event type
                    event_type = response.get("type", "unknown")
                    response_count += 1

                    if event_type == "tool_use":
                        tool = response.get('tool', 'unknown')
                        args = response.get('args', {})
                        print(f"\n[TOOL_CALL] Tool: {tool}")
                        print(f"  Args: {args}")
                    elif event_type == "tool_result":
                        result = response.get('result', {})
                        count = result.get('count', 0) if isinstance(result, dict) else 0
                        tool = response.get('tool', 'unknown')
                        print(f"\n[TOOL_RESULT] Tool: {tool}")
                        print(f"  Count: {count}")
                    elif event_type == "reasoning":
                        print(f"\n[REASONING] Received")
                    elif event_type == "final":
                        print(f"\n[FINAL] Response received")
                    elif event_type == "alert":
                        threat = response.get('threat', 'unknown')
                        severity = response.get('severity', 'unknown')
                        assets = response.get('assets', [])
                        print(f"\n[ALERT] Threat: {threat}, Severity: {severity}, Assets: {assets}")
                    else:
                        print(f"\n[{event_type.upper()}] Event received")

                except asyncio.TimeoutError:
                    print("\n[DONE] Response stream ended")
                    break
                except json.JSONDecodeError as e:
                    print(f"\n[ERROR] JSON decode error: {e}")
                    break
                except websockets.exceptions.ConnectionClosed:
                    print("\n[DONE] Connection closed")
                    break

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return False

    return True

if __name__ == "__main__":
    print("[TEST] Agent Auto-Trigger Logic Test\n")
    print("=" * 50)

    success = asyncio.run(test_cve_query())

    print("\n" + "=" * 50)
    if success:
        print("[SUCCESS] Test completed")
    else:
        print("[FAILED] Test failed")

    sys.exit(0 if success else 1)
