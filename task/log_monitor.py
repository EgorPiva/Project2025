import win32evtlog
import threading
from datetime import datetime
from playsound import playsound
import time  # Добавлено для работы с временными метками
from Support import enable_audit_policies

def play_alert_sound(sound_to_play: str) -> None:
    """Воспроизвести звуковой файл."""
    try:
        print(f"Playing sound: {sound_to_play}")
        playsound(sound_to_play, False)
    except Exception as e:
        print(f"Ошибка при воспроизведении звука: {e}")

# Настройки
LOG_TYPES = ['Security', 'System']  # Список типов логов для мониторинга
SERVER = None  # None для локального компьютера
SUSPICIOUS_EVENT_IDS: dict[str, str] = {
    "4625": "alert3.mp3",  # Неудачный вход
    # "4672": "alert.mp3",  # Специальные привилегии
    "4697": "alert.mp3",  # Установка службы
    "4700": "alert2.mp3",  # Создание задачи
    "4719": "alert4.mp3",  # Изменение политики аудита
    "4738": "alert5.mp3",  # Изменение объекта пользователя
    "4776": "alert.mp3",  # Неудачный вход (NTLM)
    "1102": "alert.mp3",   # Очистка журнала
    "6416": "alert2.mp3"
}

def format_event(event) -> str:
    """Форматирование события для вывода."""
    event_id = event.EventID & 0xFFFF
    time = event.TimeGenerated.Format()
    source = event.SourceName
    message = ' | '.join(str(i) for i in event.StringInserts) if event.StringInserts else 'Нет данных'
    return f"[{time}] ID: {event_id} | Источник: {source} | Сообщение: {message}"

def monitor_event_log() -> None:
    """Мониторинг событий журналов."""
    handles = {log_type: win32evtlog.OpenEventLog(SERVER, log_type) for log_type in LOG_TYPES}
    print(f"Мониторинг логов {', '.join(LOG_TYPES)}... Нажмите Ctrl+C для остановки.\n")

    # Пропуск старых событий
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    for hand in handles.values():
        win32evtlog.ReadEventLog(hand, flags, 0)

    sound_thread = None
    last_event_time = {}  # Словарь для хранения времени последнего вывода события

    while True:
        for log_type, hand in handles.items():
            events = win32evtlog.ReadEventLog(
                hand,
                win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                0
            )

            for event in events:
                event_id = str(event.EventID)
                current_time = time.time()

                # Проверяем, прошло ли больше 1 секунды с последнего вывода этого события
                if event_id in last_event_time and (current_time - last_event_time[event_id]) < 2:
                    continue

                last_event_time[event_id] = current_time  # Обновляем время последнего вывода
                if event_id in SUSPICIOUS_EVENT_IDS.keys():
                    print(f"⚠️ Обнаружено подозрительное событие в логе {log_type}! Event ID: {event_id}")
                    if not sound_thread or not sound_thread.is_alive() or sound_thread.name != SUSPICIOUS_EVENT_IDS[event_id]:
                        if event_id == "4672":
                            print("⚠️ Обнаружено событие 4672: Специальные привилегии.")
                        sound_thread = threading.Thread(target=play_alert_sound, args=(SUSPICIOUS_EVENT_IDS[event_id],))
                        sound_thread.start()
                        del last_event_time[event_id]

if __name__ == "__main__":
    try:
        enable_audit_policies()
        monitor_event_log()
    except KeyboardInterrupt:
        print("\nМониторинг остановлен.")
    except Exception as e:
        print(f"Ошибка: {e}")