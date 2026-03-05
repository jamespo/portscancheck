import unittest
from unittest.mock import patch, MagicMock
import pathlib
import sys
import io

# Import the functions we want to test
from check_portscan import parse_nmap_output, run_nmap

class TestCheckPortscan(unittest.TestCase):

    def test_parse_nmap_output(self):
        stdout = """
Nmap scan report for example.com (93.184.216.34)
Host is up (0.16s latency).
rDNS record for 93.184.216.34: example.com
Not shown: 996 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
8080/tcp closed http-proxy
"""
        expected = [
            "22/tcp  open  ssh",
            "443/tcp open  https",
            "80/tcp  open  http"  # Should be sorted
        ]
        # In sorted order: 22/tcp, 443/tcp, 80/tcp
        # wait, strings "22/tcp", "443/tcp", "80/tcp" sorted:
        # "22/tcp", "443/tcp", "80/tcp"
        # Let's see how python sorts them.
        # "2" < "4" < "8"
        
        result = parse_nmap_output(stdout)
        self.assertEqual(result, sorted(expected))

    @patch('subprocess.run')
    def test_run_nmap_success(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "22/tcp  open  ssh\n80/tcp  open  http"
        mock_run.return_value = mock_result
        
        result = run_nmap("example.com")
        self.assertEqual(result, ["22/tcp  open  ssh", "80/tcp  open  http"])
        mock_run.assert_called_once_with(['nmap', '-sT', '-Pn', 'example.com'], capture_output=True, text=True, check=True)

    @patch('subprocess.run')
    def test_run_nmap_ipv6(self, mock_run):
        mock_result = MagicMock()
        mock_result.stdout = "22/tcp  open  ssh"
        mock_run.return_value = mock_result
        
        run_nmap("example.com", "-6")
        mock_run.assert_called_once_with(['nmap', '-sT', '-Pn', '-6', 'example.com'], capture_output=True, text=True, check=True)

    @patch('pathlib.Path.mkdir')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.write_text')
    @patch('pathlib.Path.read_text')
    @patch('check_portscan.run_nmap')
    def test_main_initial_scan(self, mock_run_nmap, mock_read_text, mock_write_text, mock_exists, mock_mkdir):
        from check_portscan import main
        
        mock_run_nmap.return_value = ["22/tcp open ssh"]
        mock_exists.return_value = False
        
        with patch('sys.argv', ['check_portscan.py', 'example.com', '/tmp/scans']):
            with self.assertRaises(SystemExit) as cm:
                with patch('sys.stdout', new=io.StringIO()) as fake_out:
                    main()
            
            self.assertEqual(cm.exception.code, 0)
            self.assertIn("Initial scan", fake_out.getvalue())
            mock_write_text.assert_called_with("22/tcp open ssh")

    @patch('pathlib.Path.mkdir')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.read_text')
    @patch('check_portscan.run_nmap')
    def test_main_no_change(self, mock_run_nmap, mock_read_text, mock_exists, mock_mkdir):
        from check_portscan import main
        
        mock_run_nmap.return_value = ["22/tcp open ssh"]
        mock_exists.return_value = True
        mock_read_text.return_value = "22/tcp open ssh"
        
        with patch('sys.argv', ['check_portscan.py', 'example.com', '/tmp/scans']):
            with self.assertRaises(SystemExit) as cm:
                with patch('sys.stdout', new=io.StringIO()) as fake_out:
                    main()
            
            self.assertEqual(cm.exception.code, 0)
            self.assertIn("No changes", fake_out.getvalue())

    @patch('pathlib.Path.mkdir')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.read_text')
    @patch('check_portscan.run_nmap')
    def test_main_change_detected(self, mock_run_nmap, mock_read_text, mock_exists, mock_mkdir):
        from check_portscan import main
        
        # New port 80 opened, 22 still open
        mock_run_nmap.return_value = ["22/tcp open ssh", "80/tcp open http"]
        mock_exists.return_value = True
        mock_read_text.return_value = "22/tcp open ssh"
        
        with patch('sys.argv', ['check_portscan.py', 'example.com', '/tmp/scans']):
            with self.assertRaises(SystemExit) as cm:
                with patch('sys.stdout', new=io.StringIO()) as fake_out:
                    main()
            
            self.assertEqual(cm.exception.code, 1) # WARNING
            self.assertIn("Port changes detected", fake_out.getvalue())
            self.assertIn("OPENED: 80/tcp open http", fake_out.getvalue())

if __name__ == '__main__':
    unittest.main()
