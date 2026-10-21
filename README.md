# PE-Parser

Простой парсер PE-файлов на C.
Читает основные заголовки, секции, считает MD5/SHA256 и может выводить весь результат в JSON.

### Что умеет сейчас

- DOS + NT Header
- Optional Header (PE32 / PE32+)
- Data Directories (Export, Import, Resources)
- Section Table
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

### Пример вывода
```text
Signature: PE
Number of sections: 3
SizeOfOptionalHeader 0xE0
Magic: 0x10B (PE32)
AddressOfEntryPoint: 0x95E9E
ImageBase: 0x400000
NumberOfRvaAndSizes: 0x10
SHA256: d5c4983535d57d69fc6f8c09ff4a3838d6a61ac6b149de67b89c0c062968d9cd
MD5: 1742ad51f743c9e518abec7fc6f9451b
Export Table: RVA-0x0, Size-0x0
Import Table: RVA-0x95E4C, Size-0x4F
Resources Table: RVA-0x96000, Size-0x658
Sections:
	[0] .text
		RawSize: 0x94000
		VirtualSize: 0x93FD0
		PointerToRawData: 0x200
		RVA: 0x2000
	[1] .rsrc
		RawSize: 0x800
		VirtualSize: 0x658
		PointerToRawData: 0x94200
		RVA: 0x96000
	[2] .reloc
		RawSize: 0x200
		VirtualSize: 0xC
		PointerToRawData: 0x94A00
		RVA: 0x98000
```

### Пример вывода в JSON
```text
{
"file": {
	"path": "../samples/njratt.exe", 
	"size": 609280, 
	"type": "PE32", 
	"machine": "I386", 
	"subsystem": "WINDOWS_GUI", 
	"timestamp_raw": 1790572736
	},
"hashes": {
	"md5": "1742ad51f743c9e518abec7fc6f9451b", 
	"sha256": "d5c4983535d57d69fc6f8c09ff4a3838d6a61ac6b149de67b89c0c062968d9cd"
	},
"headers": {
	"nt_signature": "PE", 
	"nt_signature_raw": "0x4550", 
	"entry_point_rva": "0x95E9E", 
	"image_base": "0x400000", 
	"num_of_sections": "0x3", 
	"section_alignment": "0x2000", 
	"file_alignment": "0x200", 
	"major_subsystem_version": "0x6", 
	"minor_subsystem_version": "0x0", 
	"number_of_rva": "0x10"
	},
"sections": [
	{
	"name": ".text", 
	"rva": "0x2000", 
	"virtual_size": 606160, 
	"raw_size": 606208, 
	"raw_offset": "0x200", 
	"characteristics": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
	},
	{
	"name": ".rsrc", 
	"rva": "0x96000", 
	"virtual_size": 1624, 
	"raw_size": 2048, 
	"raw_offset": "0x94200", 
	"characteristics": ["CNT_INITIALIZED_DATA", "MEM_READ"]
	},
	{
	"name": ".reloc", 
	"rva": "0x98000", 
	"virtual_size": 12, 
	"raw_size": 512, 
	"raw_offset": "0x94A00", 
	"characteristics": ["CNT_INITIALIZED_DATA", "MEM_DISCARDABLE", "MEM_READ"]
	}
	]
}
```

Пока парсер довольно базовый. Постепенно будет добавляться чтение остальных частей PE.
