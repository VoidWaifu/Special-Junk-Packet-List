import socket
import struct
import random
import secrets
import time
import threading
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class WireGuardPacketTester:
    def __init__(self):
        self.working_packets = []
        self.lock = threading.Lock()
        self.total_packets = 0
        self.tested_packets = 0
        self.success_count = 0
        self.failed_count = 0
        self.target_host = "engage.cloudflareclient.com"
        self.target_port = 4500

    def print_progress(self, current, total, status=''):
        bar_length = 50
        progress = float(current) / float(total)
        filled_length = int(round(bar_length * progress))
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        stats = f"Успешно: {self.success_count} | Ошибки: {self.failed_count}"
        text = f"\r[{bar}] {progress * 100:.2f}% | {stats} | {status}"
        sys.stdout.write(text)
        sys.stdout.flush()

    def test_packet(self, packet_data, protocol_name):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            try:
                sock.sendto(packet_data, (self.target_host, self.target_port))
                
                try:
                    response, addr = sock.recvfrom(2048)
                    return True, [f"{self.target_host}:{self.target_port}"]
                except socket.timeout:
                    return True, [f"{self.target_host}:{self.target_port}"]
                    
            except Exception as e:
                return False, []
            finally:
                sock.close()
                    
        except Exception as e:
            return False, []

    def generate_packets(self):
        packets = []
        
        for i in range(2500):
            dns_packet = self._create_dns_packet()
            packets.append((dns_packet, f"DNS_{i}"))
        
        for i in range(2500):
            sip_packet = self._create_sip_packet()
            packets.append((sip_packet, f"SIP_{i}"))
            
        return packets

    def _create_dns_packet(self):
        domains = ["google.com", "yandex.ru", "github.com", "apple.com"]
        domain = random.choice(domains)
        
        transaction_id = secrets.token_bytes(2)
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        
        domain_parts = domain.split('.')
        qname = b''
        for part in domain_parts:
            qname += bytes([len(part)]) + part.encode()
        qname += b'\x00'
        
        qtype = b'\x00\x01'
        qclass = b'\x00\x01'
        
        return transaction_id + flags + questions + answers + authority + additional + qname + qtype + qclass

    def _create_sip_packet(self):
        call_id = secrets.token_hex(16)
        branch = f"z9hG4bK{secrets.token_hex(12)}"
        tag = secrets.token_hex(8)
        
        local_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        
        sip_packet = f"""INVITE sip:user@domain.com SIP/2.0
Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport
Max-Forwards: 70
To: <sip:user@domain.com>
From: "Caller" <sip:caller@domain.com>;tag={tag}
Call-ID: {call_id}
CSeq: {random.randint(100000, 999999)} INVITE
Contact: <sip:caller@{local_ip}:5060>
User-Agent: MySIPClient/1.0
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY
Supported: replaces
Content-Type: application/sdp
Content-Length: 0

""".replace('\n', '\r\n').encode()
        
        return sip_packet

    def run_test(self):
        print("🔧 WireGuard Packet Tester - Запуск тестирования")
        print(f"🎯 Целевой сервер: {self.target_host}:{self.target_port}")
        
        packets = self.generate_packets()
        self.total_packets = len(packets)
        self.tested_packets = 0
        self.success_count = 0
        self.failed_count = 0
        
        print(f"📦 Сгенерировано {self.total_packets} пакетов")
        print("🔄 Начало тестирования...")
        print("⏳ Ожидайте завершения процесса\n")
        
        working_count = 0
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_packet = {
                executor.submit(self._test_with_timeout, packet_data, protocol_name, 10): (packet_data, protocol_name) 
                for packet_data, protocol_name in packets
            }
            
            for future in as_completed(future_to_packet):
                packet_data, protocol_name = future_to_packet[future]
                try:
                    result, successful_services = future.result()
                    
                    if result and successful_services:
                        with self.lock:
                            packet_hex = f"<b 0x{packet_data.hex()}>"
                            
                            self.working_packets.append({
                                'I': packet_hex,
                                'successful_services': successful_services
                            })
                            working_count += 1
                            self.success_count += 1
                    else:
                        self.failed_count += 1
                
                except Exception as e:
                    self.failed_count += 1
                
                self.tested_packets += 1
                status = f"Текущий: {protocol_name}"
                self.print_progress(self.tested_packets, self.total_packets, status)
        
        print(f"\n\n📊 Результаты тестирования:")
        print(f"   ✅ Успешных пакетов: {self.success_count}")
        print(f"   ❌ Неудачных пакетов: {self.failed_count}")
        print(f"   📨 Всего протестировано: {self.tested_packets}")
        
        return self.working_packets

    def _test_with_timeout(self, packet_data, protocol_name, timeout=10):
        def test_func():
            return self.test_packet(packet_data, protocol_name)
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(test_func)
            try:
                return future.result(timeout=timeout)
            except Exception:
                return False, []

    def save_working_packets(self, filename="working_packets.json"):
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            filepath = os.path.join(current_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json_data = []
                for packet in self.working_packets:
                    json_data.append({
                        "I": packet['I'],
                        "successful_services": packet['successful_services']
                    })
                
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            print(f"💾 Файл с {len(self.working_packets)} рабочими пакетами сохранен: {filepath}")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка сохранения файла: {e}")
            return False

def main():
    print("🚀 WireGuard Packet Tester - Запуск системы")
    print("=" * 60)
    print("🎯 Тестирование на engage.cloudflareclient.com:4500")
    print("=" * 60)
    
    tester = WireGuardPacketTester()
    
    start_time = time.time()
    working_packets = tester.run_test()
    end_time = time.time()
    
    print(f"\n⏱️  Общее время тестирования: {(end_time - start_time):.2f} секунд")
    
    if working_packets:
        print(f"\n✅ Найдено {len(working_packets)} рабочих пакетов!")
        
        tester.save_working_packets()
        
        print(f"\n🎉 Тестирование успешно завершено")
        print(f"📁 Файл с пакетами сохранен в текущей директории")
        print(f"🔢 Количество рабочих пакетов: {len(working_packets)}")
        
    else:
        print("\n❌ Рабочие пакеты не обнаружены.")

if __name__ == "__main__":
    main()
