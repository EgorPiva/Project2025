import subprocess

audit_categories = {
    
    "Система": "{69979848-797A-11D9-BED3-505054503030}",
    "Вход/выход": "{69979849-797A-11D9-BED3-505054503030}",
    "Доступ к объектам": "{6997984A-797A-11D9-BED3-505054503030}",
    "Использование прав": "{6997984B-797A-11D9-BED3-505054503030}",
    "Подробное отслеживание": "{6997984C-797A-11D9-BED3-505054503030}",
    "Изменение политики": "{6997984D-797A-11D9-BED3-505054503030}",
    "Учетные записи": "{6997984E-797A-11D9-BED3-505054503030}",
    "Доступ к службе каталогов (DS)": "{6997984F-797A-11D9-BED3-505054503030}",
    "Вход учетной записи": "{69979850-797A-11D9-BED3-505054503030}"
}

def enable_audit_policies():
    if not is_admin():
        print("Требуются права администратора! Запустите скрипт от имени администратора.")
        return 
        # exit(0)
    
    print("=== Проверка и настройка аудитов безопасности ===")
    try:
        for name, guid in audit_categories.items():
            
            # аудит для успешных и неудачных событий
            subprocess.run(
                f'auditpol /set /category:"{guid}" /success:enable /failure:enable',
                shell=True,
                check=True
            )
            print(f"[+] {name} успешно включен")
            
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при настройке аудита: {e}")
    except Exception as e:
        print(f"Неизвестная ошибка: {e}")
    
    print("=== Операция завершена ===")

# Проверка прав администратора
def is_admin():
    try:
        return subprocess.run(
            "net session", 
            shell=True, 
            stderr=subprocess.PIPE, 
            stdout=subprocess.PIPE
        ).returncode == 0
    except:
        return False

if __name__ == "__main__":
    if not is_admin():
        print("Требуются права администратора! Запустите скрипт от имени администратора.")
    else:
        print("=== Проверка и настройка аудитов безопасности ===")
        enable_audit_policies()
        print("=== Операция завершена ===")