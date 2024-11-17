import subprocess
from unittest.mock import patch, MagicMock
from apps.caf.ADBCore import ADBCore
from django.test import TestCase
import logging
import os, time
import socket
import threading
import psutil

logger = logging.getLogger(__name__)

# class ADBCoreTestCase(TestCase):
#     """
#     ADBCoreTestCase
#
#     A unit test case for testing ADBCore functionalities, specifically focusing on managing ADB forward ports.
#
#     setUp():
#         Initializes the ADBCore instance and attempts to start the adb server. Fails the test if unable to start the server.
#
#     test_adb_forward_sequence():
#         Tests the adb forward sequence by performing the following steps:
#             1. Displays the initial adb forward list.
#             2. Creates a first adb forward and verifies its creation.
#             3. Displays the adb forward list after creating the first forward.
#             4. Creates a second adb forward and verifies its creation.
#             5. Displays the adb forward list after creating the second forward.
#             6. Deletes all adb forwards and verifies the deletion.
#             7. Displays the adb forward list after removing all forwards and verifies it is empty.
#     """
#     def setUp(self):
#         # Initialize the ADBCore instance
#         self.adb_core = ADBCore()
#         self.device = "YOUR_ID"  # Replace with your device ID if necessary
#
#         # Start the adb server
#         rc, out, err = self.adb_core.adb(['start-server'])
#         if rc != 0:
#             self.fail(f"Failed to start adb server: {err}")
#
#     def test_adb_forward_sequence(self):
#         # Step 1: Show adb forward list
#         forwards = self.adb_core.adb_forward_list(device=self.device)
#         print("\nStep 1: Initial adb forward list:")
#         for forward in forwards:
#             print(forward)
#         if not forwards:
#             print("No adb forwards found.")
#
#         # Step 2: Create 1 adb forward
#         local_port1 = self.adb_core.adb_forward_generator(device=self.device)
#         self.assertIsNotNone(local_port1, "Failed to set up first adb forward")
#         print(f"\nStep 2: Created first adb forward on local port {local_port1}")
#
#         # Step 3: Show adb forward list
#         forwards = self.adb_core.adb_forward_list(device=self.device)
#         print("\nStep 3: Adb forward list after creating first forward:")
#         for forward in forwards:
#             print(forward)
#
#         # Step 4: Create another adb forward
#         local_port2 = self.adb_core.adb_forward_generator(device=self.device)
#         self.assertIsNotNone(local_port2, "Failed to set up second adb forward")
#         print(f"\nStep 4: Created second adb forward on local port {local_port2}")
#
#         # Step 5: Show adb forward list
#         forwards = self.adb_core.adb_forward_list(device=self.device)
#         print("\nStep 5: Adb forward list after creating second forward:")
#         for forward in forwards:
#             print(forward)
#
#         # Step 6: Delete all adb forwards
#         success = self.adb_core.adb_forward_remove_all(device=self.device)
#         self.assertTrue(success, "Failed to remove all adb forwards")
#         print("\nStep 6: All adb forwards have been removed.")
#
#         # Step 7: Show adb forward list
#         forwards = self.adb_core.adb_forward_list(device=self.device)
#         print("\nStep 7: Adb forward list after removing all forwards:")
#         if forwards:
#             for forward in forwards:
#                 print(forward)
#         else:
#             print("No adb forwards found.")
#         self.assertEqual(len(forwards), 0, "Adb forward list should be empty after removing all forwards.")

