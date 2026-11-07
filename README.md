# PE-Parser

Парсер PE-файлов на C для Linux

### Что делает

- DOS + NT Header
- Optional Header (PE32 / PE32+)
- Data Directories (Export, Import, Resources)
- Section Table
- Section's entropy
- Import Table
- Export Table
- MD5 и SHA256 всего файла
- Вывод результата в консоль или в файл report_<filename>.json

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
