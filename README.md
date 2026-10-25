# PE-Parser

Парсер PE-файлов на C.
Читает основные заголовки, секции, Import и Export Table, считает MD5/SHA256 и может выводить весь результат в JSON.

### Что умеет

- DOS + NT Header
- Optional Header (PE32 / PE32+)
- Data Directories (Export, Import, Resources)
- Section Table
- Import Table
- Export Table
- MD5 и SHA256 всего файла
- Вывод результата в консоль или в файл output.json

### Сборка

Нужен `gcc` и OpenSSL:

```bash
sudo apt install libssl-dev # debian/ubuntu
make
```

### Использование
```bash
./parser <file.exe>
./parser <file.exe> -json
``` 
