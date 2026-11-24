import xml.etree.ElementTree as ET
import hashlib
import json
import re
import base64
import pymorphy3
from deep_translator import GoogleTranslator

# 1. Читаем настройки из config.json
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

INPUT_FILE = config["input_file"]
OUTPUT_FILE = config["output_file"]
TARGET_LANG = config["target_lang"]
DO_TRANSLATE = config["translate"]

# Справочники
VEGGIES = [
    "Яблоко", "Груша", "Банан", "Ананас", "Апельсин", "Лимон", "Киви", "Манго",
    "Арбуз", "Дыня", "Помидор", "Огурец", "Картофель", "Морковь", "Тыква",
    "Кабачок", "Баклажан", "Персик", "Абрикос", "Слива", "Вишня", "Малина"
]

NAMES = [
    "Иван", "Петр", "Сергей", "Михаил", "Анна", "Мария", "Елена", "Ольга",
    "Алексей", "Дмитрий", "Евгений", "Наталья", "Татьяна", "Игорь", "Владимир"
]

# Инструменты для склонения слов и перевода
morph = pymorphy3.MorphAnalyzer()
translator = GoogleTranslator(source="ru", target=TARGET_LANG)
ru_to_en = GoogleTranslator(source="ru", target="en")
cache_translate = {}  # Запоминаем переводы


def get_number(text):
    hash_str = hashlib.md5(text.encode("utf-8")).hexdigest()
    return int(hash_str, 16)


def translate(text):
    #Переводит текст на язык из config.json
    if not DO_TRANSLATE or TARGET_LANG == "ru":
        return text
    if text not in cache_translate:
        try:
            cache_translate[text] = translator.translate(text)
        except Exception:
            cache_translate[text] = text
    return cache_translate[text]


def to_adjective(word):
    #Делает из существительного (Тыква) прилагательное (Тыквенный)
    parsed = morph.parse(word)[0]
    for form in parsed.lexeme:
        if "ADJF" in form.tag:
            return form.word.capitalize()
    return word + "овый"


def anonymize_object(text):
    #Обезличивает подстанции, ЛЭП и юрлица: овощ -> прилагательное + уникальный номер
    num = get_number(text)
    veg = VEGGIES[num % len(VEGGIES)]
    adj = to_adjective(veg)
    unique_code = num % 10000  # Чтобы не было одинаковых названий у разных объектов

    # Сохраняем тип объекта/компании, если он есть в названии
    prefix = ""
    for word in ["ПС", "ТП", "РП", "ЛЭП", "ООО", "АО", "ПАО"]:
        if word in text.upper():
            prefix = word + " "
            break

    new_name = f"{prefix}{adj}-{unique_code}"
    return translate(new_name)


def anonymize_person(text, field_type):
    #Обезличивает людей: одно имя из справочника -> ФИО, email и улица
    num = get_number(text)
    name = NAMES[num % len(NAMES)]

    if field_type == "fio":
        fio = f"{name} {name}ов {name}ович"
        return translate(fio)

    elif field_type == "email":
        eng_name = ru_to_en.translate(name).lower()
        return f"{eng_name}{num % 1000}@example.com"

    elif field_type == "address":
        street = f"ул. {name}ская, д. {(num % 99) + 1}"
        return translate(street)


def anonymize_digits(text):
    #Меняет цифры (ИНН, КПП, телефоны, паспорта) на случайные, сохраняя длину и знаки
    num = get_number(text)
    new_text = ""
    for i, ch in enumerate(text):
        if ch.isdigit():
            new_text += str((num + i * 7) % 10)
        else:
            new_text += ch
    return new_text


def anonymize_url(url):
    #Обезличивает http-ссылки, только если они ведут на энергообъекты или документы
    markers = ["substation", "ps", "tp", "lep", "object", "doc", "scheme", "energo"]
    if any(m in url.lower() for m in markers):
        return f"https://anonymized-grid.local_{get_number(url) % 100000}"
    return url


def anonymize_free_text(text):
    #Чистит комментарии и логи: скрывает длинные числа и ссылки на объекты
    text = re.sub(r"\d{6,}", "***", text)
    text = re.sub(r'https?://[^\s<>"]+', lambda m: anonymize_url(m.group(0)), text)
    return translate(text)


def anonymize_attachment(b64_data):
    #Проверяет бинарные вложения (Base64): картинки заменяет заглушкой, текст чистит
    try:
        raw = base64.b64decode(b64_data)
        # Если это картинка (PNG/JPEG) — ставим пустой квадрат 1x1 пиксель
        if raw.startswith(b"\x89PNG") or raw.startswith(b"\xff\xd8"):
            return "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        # Если это PDF — заменяем текстовой заглушкой
        if raw.startswith(b"%PDF"):
            return base64.b64encode(b"Anonymized Document").decode("utf-8")
        # Если внутри текст (лог) — чистим и кодируем обратно
        cleaned = anonymize_free_text(raw.decode("utf-8"))
        return base64.b64encode(cleaned.encode("utf-8")).decode("utf-8")
    except Exception:
        return b64_data


def process_field(tag, value):
    #Определяет по названию тега, как именно нужно обезличить значение
    t = tag.lower()

    if value.startswith("http://") or value.startswith("https://"):
        return anonymize_url(value)

    if any(w in t for w in ["binary", "attachment", "image", "file", "blob"]) and len(value) > 100:
        return anonymize_attachment(value)

    if any(w in t for w in ["person", "fio", "firstname", "lastname", "employee", "subscriber"]):
        return anonymize_person(value, "fio")

    if "email" in t or "mail" in t:
        return anonymize_person(value, "email")

    if "address" in t or "street" in t:
        return anonymize_person(value, "address")

    if any(w in t for w in ["inn", "kpp", "phone", "passport", "account", "tab", "number", "inv"]):
        return anonymize_digits(value)

    if any(w in t for w in ["comment", "desc", "log", "note"]):
        return anonymize_free_text(value)

    if "name" in t:
        return anonymize_object(value)

    return value


# 3. Потоковая обработка XML
ET.register_namespace("rdf", "http://w3.org")
ET.register_namespace("cim", "http://iec.ch")

print(f"Обработка {INPUT_FILE}...")

with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    out.write('<?xml version="1.0" encoding="utf-8"?>\n')
    out.write('<rdf:RDF xmlns:rdf="http://w3.org" xmlns:cim="http://iec.ch">\n')

    count = 0
    for event, elem in ET.iterparse(INPUT_FILE, events=("end",)):
        tag_name = elem.tag.split("}")[-1]

        # Обезличиваем текст внутри тега
        if elem.text and elem.text.strip():
            elem.text = process_field(tag_name, elem.text.strip())

        # Обезличиваем атрибуты тега (если там есть name или http-ссылка)
        for attr_key, attr_val in elem.attrib.items():
            clean_key = attr_key.split("}")[-1]
            if "name" in clean_key.lower() or attr_val.startswith("http"):
                elem.attrib[clean_key] = process_field(clean_key, attr_val)

        # Записываем готовую сущность в файл и сразу удаляем из памяти
        if elem.attrib:
            ET.indent(elem, space="    ")
            out.write(ET.tostring(elem, encoding="unicode") + "\n")
            elem.clear()
            count += 1

            if count % 5000 == 0:
                print(f"Обработано: {count} элементов...")

    out.write("</rdf:RDF>")

print(f"Готово! Обработано {count} элементов. Результат сохранен в {OUTPUT_FILE}")
