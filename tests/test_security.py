"""
Test suite for the Physical Security System security modules.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock, call
from src.security.alert_system import AlertSystem
from src.security.system_monitor import SystemMonitor
from src.security.process_manager import ProcessManager


class TestAlertSystem:
    """Test cases for AlertSystem."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.alert_system = AlertSystem()
    
    def test_initialization(self):
        """Test proper initialization of AlertSystem."""
        assert self.alert_system.alert_active is False
        assert self.alert_system.recording_alert_active is False
        assert self.alert_system.grace_period_active is False
        assert self.alert_system.grace_period_start is None
        assert self.alert_system.alert_start_time is None
        assert self.alert_system.grace_period_duration == 30
    
    def test_is_alert_active(self):
        """Test alert active status check."""
        assert self.alert_system.is_alert_active() is False
        
        self.alert_system.alert_active = True
        assert self.alert_system.is_alert_active() is True
    
    def test_is_recording_grace_period_active_false(self):
        """Test grace period check when not active."""
        result = self.alert_system.is_recording_grace_period_active()
        assert result is False
    
    def test_is_recording_grace_period_active_expired(self):
        """Test grace period check when expired."""
        # Set grace period to have started 60 seconds ago (expired)
        self.alert_system.grace_period_active = True
        self.alert_system.grace_period_start = time.time() - 60
        
        result = self.alert_system.is_recording_grace_period_active()
        assert result is False
        assert self.alert_system.grace_period_active is False
    
    def test_is_recording_grace_period_active_valid(self):
        """Test grace period check when still active."""
        # Set grace period to have started 10 seconds ago (still active)
        self.alert_system.grace_period_active = True
        self.alert_system.grace_period_start = time.time() - 10
        
        result = self.alert_system.is_recording_grace_period_active()
        assert result is True
    
    @patch('src.security.alert_system.SecurityUtils')
    def test_start_grace_period(self, mock_security_utils):
        """Test starting grace period."""
        self.alert_system.start_grace_period()
        
        assert self.alert_system.grace_period_active is True
        assert self.alert_system.grace_period_start is not None
        mock_security_utils.log_security_event.assert_called_once_with(
            "GRACE_PERIOD_START", "Recording alert grace period started"
        )
    
    @patch('src.security.alert_system.threading.Thread')
    @patch('src.security.alert_system.SecurityOverlay')
    def test_trigger_mobile_alert(self, mock_overlay, mock_thread):
        """Test triggering mobile phone alert."""
        mock_overlay_instance = Mock()
        mock_overlay.return_value = mock_overlay_instance
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        self.alert_system.trigger_mobile_alert()
        
        assert self.alert_system.alert_active is True
        assert self.alert_system.alert_start_time is not None
        mock_thread_instance.start.assert_called_once()
        mock_thread.assert_called_once()
    
    @patch('src.security.alert_system.threading.Thread')
    @patch('src.security.alert_system.SecurityOverlay')
    def test_trigger_recording_alert(self, mock_overlay, mock_thread):
        """Test triggering recording tool alert."""
        mock_overlay_instance = Mock()
        mock_overlay.return_value = mock_overlay_instance
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        self.alert_system.trigger_recording_alert(['obs64.exe'])
        
        assert self.alert_system.recording_alert_active is True
        mock_thread_instance.start.assert_called_once()
        mock_thread.assert_called_once()
    
    def test_deactivate_alert(self):
        """Test deactivating alert."""
        # Set up active alert
        self.alert_system.alert_active = True
        self.alert_system.alert_start_time = time.time()
        
        self.alert_system.deactivate_alert()
        
        assert self.alert_system.alert_active is False
        assert self.alert_system.alert_start_time is None
    
    def test_deactivate_recording_alert(self):
        """Test deactivating recording alert."""
        # Set up active recording alert
        self.alert_system.recording_alert_active = True
        
        self.alert_system.deactivate_recording_alert()
        
        assert self.alert_system.recording_alert_active is False


class TestSystemMonitor:
    """Test cases for SystemMonitor."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.monitor = SystemMonitor()
    
    def test_initialization(self):
        """Test proper initialization of SystemMonitor."""
        assert self.monitor.recording_tools is not None
        assert len(self.monitor.recording_tools) > 0
        assert 'obs64.exe' in self.monitor.recording_tools
        assert 'bandicam.exe' in self.monitor.recording_tools
    
    @patch('src.security.system_monitor.psutil.process_iter')
    def test_get_running_processes(self, mock_process_iter):
        """Test getting running processes."""
        # Mock process data
        mock_proc1 = Mock()
        mock_proc1.info = {'pid': 1234, 'name': 'notepad.exe'}
        mock_proc2 = Mock()
        mock_proc2.info = {'pid': 5678, 'name': 'obs64.exe'}
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        processes = self.monitor.get_running_processes()
        
        assert len(processes) == 2
        assert processes[0]['name'] == 'notepad.exe'
        assert processes[1]['name'] == 'obs64.exe'
    
    @patch('src.security.system_monitor.psutil.process_iter')
    def test_detect_recording_tools(self, mock_process_iter):
        """Test detecting recording tools."""
        # Mock process with recording tool
        mock_proc = Mock()
        mock_proc.info = {'pid': 1234, 'name': 'obs64.exe'}
        
        mock_process_iter.return_value = [mock_proc]
        
        detected = self.monitor.detect_recording_tools()
        
        assert len(detected) == 1
        assert 'obs64.exe' in detected
    
    @patch('src.security.system_monitor.psutil.process_iter')
    def test_detect_recording_tools_none(self, mock_process_iter):
        """Test detecting no recording tools."""
        # Mock process without recording tools
        mock_proc = Mock()
        mock_proc.info = {'pid': 1234, 'name': 'notepad.exe'}
        
        mock_process_iter.return_value = [mock_proc]
        
        detected = self.monitor.detect_recording_tools()
        
        assert len(detected) == 0
    
    def test_check_recording_alert_needed_with_tools(self):
        """Test recording alert check with detected tools."""
        detected_tools = ['obs64.exe', 'bandicam.exe']
        
        result = self.monitor.check_recording_alert_needed(detected_tools)
        
        assert result is True
    
    def test_check_recording_alert_needed_no_tools(self):
        """Test recording alert check without detected tools."""
        detected_tools = []
        
        result = self.monitor.check_recording_alert_needed(detected_tools)
        
        assert result is False
    
    @patch('src.security.system_monitor.psutil.virtual_memory')
    @patch('src.security.system_monitor.psutil.cpu_percent')
    def test_get_system_stats(self, mock_cpu_percent, mock_virtual_memory):
        """Test getting system statistics."""
        # Mock system stats
        mock_memory = Mock()
        mock_memory.total = 8589934592  # 8GB
        mock_memory.available = 4294967296  # 4GB
        mock_memory.percent = 50.0
        mock_virtual_memory.return_value = mock_memory
        mock_cpu_percent.return_value = 25.5
        
        stats = self.monitor.get_system_stats()
        
        assert stats['cpu_percent'] == 25.5
        assert stats['memory_percent'] == 50.0
        assert stats['memory_total'] == 8589934592
        assert stats['memory_available'] == 4294967296
    
    @patch('src.security.system_monitor.psutil.process_iter')
    def test_get_process_count(self, mock_process_iter):
        """Test getting process count."""
        mock_processes = [Mock() for _ in range(150)]
        mock_process_iter.return_value = mock_processes
        
        count = self.monitor.get_process_count()
        
        assert count == 150


class TestProcessManager:
    """Test cases for ProcessManager."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.process_manager = ProcessManager()
    
    def test_initialization(self):
        """Test proper initialization of ProcessManager."""
        assert self.process_manager.blocked_processes == set()
        assert hasattr(self.process_manager, 'recording_tools')
    
    @patch('src.security.process_manager.psutil.process_iter')
    def test_find_process_by_name(self, mock_process_iter):
        """Test finding process by name."""
        # Mock processes
        mock_proc1 = Mock()
        mock_proc1.info = {'pid': 1234, 'name': 'notepad.exe'}
        mock_proc2 = Mock()
        mock_proc2.info = {'pid': 5678, 'name': 'obs64.exe'}
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        found_processes = self.process_manager.find_process_by_name('obs64.exe')
        
        assert len(found_processes) == 1
        assert found_processes[0]['pid'] == 5678
        assert found_processes[0]['name'] == 'obs64.exe'
    
    @patch('src.security.process_manager.psutil.Process')
    def test_terminate_process_success(self, mock_process_class):
        """Test successful process termination."""
        mock_process = Mock()
        mock_process_class.return_value = mock_process
        
        result = self.process_manager.terminate_process(1234)
        
        assert result is True
        mock_process.terminate.assert_called_once()
    
    @patch('src.security.process_manager.psutil.Process')
    def test_terminate_process_failure(self, mock_process_class):
        """Test process termination failure."""
        mock_process = Mock()
        mock_process.terminate.side_effect = Exception("Access denied")
        mock_process_class.return_value = mock_process
        
        result = self.process_manager.terminate_process(1234)
        
        assert result is False
    
    @patch('src.security.process_manager.psutil.Process')
    def test_kill_process_success(self, mock_process_class):
        """Test successful process killing."""
        mock_process = Mock()
        mock_process_class.return_value = mock_process
        
        result = self.process_manager.kill_process(1234)
        
        assert result is True
        mock_process.kill.assert_called_once()
    
    @patch('src.security.process_manager.psutil.Process')
    def test_kill_process_failure(self, mock_process_class):
        """Test process killing failure."""
        mock_process = Mock()
        mock_process.kill.side_effect = Exception("Access denied")
        mock_process_class.return_value = mock_process
        
        result = self.process_manager.kill_process(1234)
        
        assert result is False
    
    def test_add_blocked_process(self):
        """Test adding blocked process."""
        self.process_manager.add_blocked_process('malware.exe')
        
        assert 'malware.exe' in self.process_manager.blocked_processes
    
    def test_remove_blocked_process(self):
        """Test removing blocked process."""
        # Add then remove
        self.process_manager.add_blocked_process('test.exe')
        self.process_manager.remove_blocked_process('test.exe')
        
        assert 'test.exe' not in self.process_manager.blocked_processes
    
    def test_is_process_blocked(self):
        """Test checking if process is blocked."""
        self.process_manager.add_blocked_process('blocked.exe')
        
        assert self.process_manager.is_process_blocked('blocked.exe') is True
        assert self.process_manager.is_process_blocked('allowed.exe') is False
    
    @patch.object(ProcessManager, 'find_process_by_name')
    @patch.object(ProcessManager, 'terminate_process')
    def test_block_recording_tools(self, mock_terminate, mock_find):
        """Test blocking recording tools."""
        # Mock finding OBS process
        mock_find.return_value = [{'pid': 1234, 'name': 'obs64.exe'}]
        mock_terminate.return_value = True
        
        blocked = self.process_manager.block_recording_tools()
        
        assert len(blocked) > 0
        mock_terminate.assert_called()
    
    @patch('src.security.process_manager.subprocess.run')
    def test_disable_task_manager_success(self, mock_run):
        """Test successful task manager disabling."""
        mock_run.return_value = Mock(returncode=0)
        
        result = self.process_manager.disable_task_manager()
        
        assert result is True
        mock_run.assert_called_once()
    
    @patch('src.security.process_manager.subprocess.run')
    def test_disable_task_manager_failure(self, mock_run):
        """Test task manager disabling failure."""
        mock_run.return_value = Mock(returncode=1)
        
        result = self.process_manager.disable_task_manager()
        
        assert result is False
    
    @patch('src.security.process_manager.subprocess.run')
    def test_enable_task_manager_success(self, mock_run):
        """Test successful task manager enabling."""
        mock_run.return_value = Mock(returncode=0)
        
        result = self.process_manager.enable_task_manager()
        
        assert result is True
        mock_run.assert_called_once()


class TestSecurityIntegration:
    """Integration tests for security system components."""
    
    def test_alert_system_monitor_integration(self):
        """Test integration between alert system and system monitor."""
        alert_system = AlertSystem()
        system_monitor = SystemMonitor()
        
        # Test that monitor can detect recording tools
        with patch('src.security.system_monitor.psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {'pid': 1234, 'name': 'obs64.exe'}
            mock_iter.return_value = [mock_proc]
            
            detected = system_monitor.detect_recording_tools()
            should_alert = system_monitor.check_recording_alert_needed(detected)
            
            assert len(detected) == 1
            assert should_alert is True
    
    def test_process_manager_alert_integration(self):
        """Test integration between process manager and alert system."""
        process_manager = ProcessManager()
        alert_system = AlertSystem()
        
        # Test that blocked processes can trigger alerts
        process_manager.add_blocked_process('malicious.exe')
        
        # Simulate detection and blocking flow
        is_blocked = process_manager.is_process_blocked('malicious.exe')
        assert is_blocked is True
        
        # Alert system should be able to respond
        assert alert_system.is_alert_active() is False
    
    @patch('src.security.alert_system.threading.Thread')
    @patch('src.security.alert_system.SecurityOverlay')
    def test_full_security_workflow(self, mock_overlay, mock_thread):
        """Test complete security detection and response workflow."""
        alert_system = AlertSystem()
        system_monitor = SystemMonitor()
        process_manager = ProcessManager()
        
        # Mock overlay and thread
        mock_overlay_instance = Mock()
        mock_overlay.return_value = mock_overlay_instance
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        # Simulate detection workflow
        with patch('src.security.system_monitor.psutil.process_iter') as mock_iter:
            # Mock OBS running
            mock_proc = Mock()
            mock_proc.info = {'pid': 1234, 'name': 'obs64.exe'}
            mock_iter.return_value = [mock_proc]
            
            # Step 1: Monitor detects recording tool
            detected_tools = system_monitor.detect_recording_tools()
            assert 'obs64.exe' in detected_tools
            
            # Step 2: Check if alert is needed
            alert_needed = system_monitor.check_recording_alert_needed(detected_tools)
            assert alert_needed is True
            
            # Step 3: Trigger recording alert
            alert_system.trigger_recording_alert(detected_tools)
            assert alert_system.recording_alert_active is True
            
            # Step 4: Process manager can block the tool
            with patch.object(process_manager, 'terminate_process', return_value=True):
                blocked = process_manager.block_recording_tools()
                assert len(blocked) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
