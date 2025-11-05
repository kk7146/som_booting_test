# LAN 테스트 프로그램
라즈베리파이에서 ICMP Echo Request(ping)를 감지해 **GPIO를 1초간 HIGH로 펄스**하고, **마지막 핑 3분 후 재펄스**, **7분 동안 핑이 없으면 경고 로그**를 남깁니다.

## 동작 요약

* 핑 수신 즉시: **GPIO HIGH → 1초 후 LOW**
* 마지막 핑 + **3분 후**: 자동 **재펄스(1초)**
* 마지막 핑 + **7분 무응답**: 경고 로그 출력
* `SOM_IP`를 설정하면 해당 소스 IP에서 온 핑만 처리

## Config

스크립트 상단에서 필요 시 수정:

```python
GPIO_PIN = 17
SOM_IP = None
PULSE_SEC = 1.0
REPULSE_DELAY_SEC = 3 * 60
ALARM_SEC = 7 * 60
```
GPIO_PIN : 사용할 핀  
SOM_IP : 특정 송신 IP만 허용하려면 "192.168.x.x"  
PULSE_SEC : Low 유지 길이(초)  
REPULSE_DELAY_SEC : 펄스 재전송 타이밍  
ALARM_SEC : SoM 부팅되지 않거나, 랜선 연결이 안되는 것을 판단하기 위한 시간  

## 실행
```bash
sh start.sh
```
