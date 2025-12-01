#!/usr/bin/env python3
"""
MITM (Man-in-the-Middle) Proxy for SecureChat testing.

Transparent TCP proxy that intercepts and allows modification of SecureChat messages
for security testing (tampering, replay attacks, protocol violations).

Architecture: Client:5555 → Proxy:5001 → Server:9999

Usage:
    proxy = MITMProxy(listen_port=5001, target_port=9999)
    proxy.on_client_msg = lambda msg: tamper_ciphertext(msg)
    proxy.start()
    proxy.inject_to_server(replayed_message)
    proxy.stop()
"""

import socket
import struct
import json
import threading
import time
import logging
import base64
from typing import Callable, Optional, Dict, Any, Tuple

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s - PROXY - %(message)s'
)
logger = logging.getLogger(__name__)


class MITMProxy:
    """
    Transparent TCP proxy for SecureChat protocol testing.
    
    Intercepts length-prefixed JSON messages and allows modification/injection.
    """
    
    def __init__(
        self,
        listen_port: int = 5001,
        target_host: str = '127.0.0.1',
        target_port: int = 9999,
        buffer_size: int = 4096
    ):
        """
        Initialize MITM proxy.
        
        Args: listen_port, target_host, target_port, buffer_size
        """
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.buffer_size = buffer_size
        
        self.listen_socket: Optional[socket.socket] = None
        self.running = False
        self.threads = []
        
        # Message interception callbacks
        self.on_client_msg: Optional[Callable] = None  # Called with msg dict
        self.on_server_msg: Optional[Callable] = None  # Called with msg dict
        
        # Message injection queues
        self.inject_to_client_queue = []
        self.inject_to_server_queue = []
        
        # Statistics
        self.stats = {
            'client_msgs': 0,
            'server_msgs': 0,
            'bytes_c2s': 0,
            'bytes_s2c': 0,
            'injected': 0,
            'modified': 0,
        }
    
    def start(self) -> None:
        """Start listening for client connections."""
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind(('127.0.0.1', self.listen_port))
        self.listen_socket.listen(5)
        
        self.running = True
        logger.info(f"MITM Proxy listening on 127.0.0.1:{self.listen_port}")
        logger.info(f"Forwarding to {self.target_host}:{self.target_port}")
        
        # Start accept thread
        accept_thread = threading.Thread(target=self._accept_connections)
        accept_thread.daemon = True
        accept_thread.start()
        self.threads.append(accept_thread)
    
    def stop(self) -> None:
        """Stop the proxy."""
        self.running = False
        if self.listen_socket:
            self.listen_socket.close()
        
        # Wait for threads
        for thread in self.threads:
            thread.join(timeout=2)
        
        logger.info("MITM Proxy stopped")
    
    def _accept_connections(self) -> None:
        """Accept incoming client connections."""
        while self.running:
            try:
                client_sock, client_addr = self.listen_socket.accept()
                logger.info(f"Client connected: {client_addr}")
                
                # Connect to server
                try:
                    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_sock.connect((self.target_host, self.target_port))
                    logger.info(f"Connected to server: {self.target_host}:{self.target_port}")
                    
                    # Start forwarding threads
                    c2s_thread = threading.Thread(
                        target=self._forward_client_to_server,
                        args=(client_sock, server_sock)
                    )
                    s2c_thread = threading.Thread(
                        target=self._forward_server_to_client,
                        args=(server_sock, client_sock)
                    )
                    
                    c2s_thread.daemon = True
                    s2c_thread.daemon = True
                    c2s_thread.start()
                    s2c_thread.start()
                    
                    self.threads.extend([c2s_thread, s2c_thread])
                    
                except Exception as e:
                    logger.error(f"Failed to connect to server: {e}")
                    client_sock.close()
            
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")
                break
    
    def _forward_client_to_server(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket
    ) -> None:
        """Forward messages from client to server."""
        try:
            while self.running:
                # Check injection queue
                if self.inject_to_server_queue:
                    msg = self.inject_to_server_queue.pop(0)
                    self._send_message(server_sock, msg)
                    self.stats['injected'] += 1
                    logger.warning(f"INJECTED to server: {msg.get('type')}")
                    continue
                
                # Receive from client
                data = client_sock.recv(self.buffer_size)
                if not data:
                    break
                
                # Try to parse as SecureChat message
                modified_data = self._process_client_message(data)
                
                self.stats['bytes_c2s'] += len(data)
                
                # Forward to server
                server_sock.sendall(modified_data)
        
        except Exception as e:
            if self.running:
                logger.error(f"C2S forward error: {e}")
        finally:
            client_sock.close()
            server_sock.close()
            logger.info("C2S channel closed")
    
    def _forward_server_to_client(
        self,
        server_sock: socket.socket,
        client_sock: socket.socket
    ) -> None:
        """Forward messages from server to client."""
        try:
            while self.running:
                # Check injection queue
                if self.inject_to_client_queue:
                    msg = self.inject_to_client_queue.pop(0)
                    self._send_message(client_sock, msg)
                    self.stats['injected'] += 1
                    logger.warning(f"INJECTED to client: {msg.get('type')}")
                    continue
                
                # Receive from server
                data = server_sock.recv(self.buffer_size)
                if not data:
                    break
                
                # Try to parse as SecureChat message
                modified_data = self._process_server_message(data)
                
                self.stats['bytes_s2c'] += len(data)
                
                # Forward to client
                client_sock.sendall(modified_data)
        
        except Exception as e:
            if self.running:
                logger.error(f"S2C forward error: {e}")
        finally:
            server_sock.close()
            client_sock.close()
            logger.info("S2C channel closed")
    
    def _process_client_message(self, data: bytes) -> bytes:
        """
        Process message from client to server.
        
        Parses length-prefixed JSON: [4 bytes length][JSON message]
        """
        if len(data) < 4:
            return data
        
        try:
            # Parse length prefix
            length = struct.unpack('>I', data[:4])[0]
            
            if len(data) < 4 + length:
                return data
            
            # Parse JSON message
            msg_json = data[4:4+length]
            msg_dict = json.loads(msg_json)
            
            self.stats['client_msgs'] += 1
            logger.debug(f"C→S: {msg_dict.get('type')}")
            
            # Call callback if registered
            if self.on_client_msg:
                modified_dict = self.on_client_msg(msg_dict)
                if modified_dict is not None and modified_dict != msg_dict:
                    self.stats['modified'] += 1
                    logger.warning(f"MODIFIED C→S message: {modified_dict.get('type')}")
                    return self._encode_message(modified_dict) + data[4+length:]
            
            return data
        
        except Exception as e:
            logger.debug(f"Could not parse C→S message: {e}")
            return data
    
    def _process_server_message(self, data: bytes) -> bytes:
        """
        Process message from server to client.
        """
        if len(data) < 4:
            return data
        
        try:
            # Parse length prefix
            length = struct.unpack('>I', data[:4])[0]
            
            if len(data) < 4 + length:
                return data
            
            # Parse JSON message
            msg_json = data[4:4+length]
            msg_dict = json.loads(msg_json)
            
            self.stats['server_msgs'] += 1
            logger.debug(f"S→C: {msg_dict.get('type')}")
            
            # Call callback if registered
            if self.on_server_msg:
                modified_dict = self.on_server_msg(msg_dict)
                if modified_dict is not None and modified_dict != msg_dict:
                    self.stats['modified'] += 1
                    logger.warning(f"MODIFIED S→C message: {modified_dict.get('type')}")
                    return self._encode_message(modified_dict) + data[4+length:]
            
            return data
        
        except Exception as e:
            logger.debug(f"Could not parse S→C message: {e}")
            return data
    
    def _encode_message(self, msg_dict: Dict[str, Any]) -> bytes:
        """Encode message as SecureChat protocol."""
        msg_json = json.dumps(msg_dict).encode('utf-8')
        length = len(msg_json)
        return struct.pack('>I', length) + msg_json
    
    def _send_message(self, sock: socket.socket, msg_dict: Dict[str, Any]) -> None:
        """Send a message through socket."""
        data = self._encode_message(msg_dict)
        sock.sendall(data)
    
    def inject_to_server(self, msg: Dict[str, Any]) -> None:
        """Inject a message to be sent to server."""
        self.inject_to_server_queue.append(msg)
    
    def inject_to_client(self, msg: Dict[str, Any]) -> None:
        """Inject a message to be sent to client."""
        self.inject_to_client_queue.append(msg)
    
    def get_stats(self) -> Dict[str, int]:
        """Get proxy statistics."""
        return self.stats.copy()


# Message tampering utilities

def tamper_ciphertext(msg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tamper with message ciphertext (flip one bit).
    
    Should cause signature verification to fail.
    """
    if 'ct' not in msg or msg['ct'] is None:
        return msg
    
    msg = msg.copy()
    ct_b64 = msg['ct']
    
    try:
        # Decode base64
        ct_bytes = base64.b64decode(ct_b64)
        
        # Flip one bit in the middle
        ct_list = list(ct_bytes)
        if ct_list:
            ct_list[len(ct_list) // 2] ^= 1
        ct_bytes = bytes(ct_list)
        
        # Re-encode
        msg['ct'] = base64.b64encode(ct_bytes).decode('utf-8')
        logger.warning(f"Tampered ciphertext: {msg['ct'][:50]}...")
        
    except Exception as e:
        logger.error(f"Could not tamper ciphertext: {e}")
    
    return msg


def tamper_timestamp(msg: Dict[str, Any], delta_ms: int = 1000) -> Dict[str, Any]:
    """
    Tamper with message timestamp.
    
    Should cause signature verification to fail.
    """
    if 'ts' not in msg:
        return msg
    
    msg = msg.copy()
    msg['ts'] = msg['ts'] + delta_ms
    logger.warning(f"Tampered timestamp: +{delta_ms}ms")
    
    return msg


def tamper_seqno(msg: Dict[str, Any], delta: int = 1) -> Dict[str, Any]:
    """
    Tamper with message sequence number.
    
    Should cause signature verification to fail or replay detection.
    """
    if 'seqno' not in msg:
        return msg
    
    msg = msg.copy()
    msg['seqno'] = msg['seqno'] + delta
    logger.warning(f"Tampered seqno: +{delta}")
    
    return msg


def tamper_signature(msg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tamper with message signature (flip one bit).
    
    Should cause signature verification to fail.
    """
    if 'sig' not in msg or msg['sig'] is None:
        return msg
    
    msg = msg.copy()
    sig_b64 = msg['sig']
    
    try:
        # Decode base64
        sig_bytes = base64.b64decode(sig_b64)
        
        # Flip one bit
        sig_list = list(sig_bytes)
        if sig_list:
            sig_list[len(sig_list) // 2] ^= 1
        sig_bytes = bytes(sig_list)
        
        # Re-encode
        msg['sig'] = base64.b64encode(sig_bytes).decode('utf-8')
        logger.warning(f"Tampered signature: {msg['sig'][:50]}...")
        
    except Exception as e:
        logger.error(f"Could not tamper signature: {e}")
    
    return msg


if __name__ == '__main__':
    # Test the proxy
    proxy = MITMProxy(listen_port=5001, target_port=5000)
    proxy.start()
    
    try:
        while True:
            time.sleep(1)
            print(f"Stats: {proxy.get_stats()}")
    except KeyboardInterrupt:
        print("\nShutting down...")
        proxy.stop()
