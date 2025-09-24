# PHP Frameworks for HNP Analysis

This directory contains the source code of PHP web frameworks used for Host Header Poisoning (HNP) vulnerability analysis. Due to the large size of framework source code, these are not included in the Git repository.

## Download Instructions

Run the following commands to download the frameworks:

### 1. Laravel
```bash
git clone --depth 1 https://github.com/laravel/laravel.git laravel
```

### 2. Symfony
```bash
git clone --depth 1 https://github.com/symfony/symfony-demo.git symfony
```

### 3. CodeIgniter
```bash
git clone --depth 1 https://github.com/codeigniter4/CodeIgniter4.git codeigniter
```

### 4. CakePHP
```bash
git clone --depth 1 https://github.com/cakephp/app.git cakephp
```

### 5. Yii
```bash
git clone --depth 1 https://github.com/yiisoft/yii2-app-basic.git yii
```

## Automated Download

Alternatively, use the framework CLI tool:

```bash
# List available frameworks
python3 ../src/framework_cli.py --list

# Download specific framework
python3 ../src/framework_cli.py --download 1  # Laravel
python3 ../src/framework_cli.py --download 2  # Symfony
python3 ../src/framework_cli.py --download 3  # CodeIgniter
python3 ../src/framework_cli.py --download 4  # CakePHP
python3 ../src/framework_cli.py --download 5  # Yii

# Download all frameworks at once
for i in {1..5}; do python3 ../src/framework_cli.py --download $i; done
```

## Framework Information

| Framework | Version | Repository | Size (approx.) |
|-----------|---------|------------|----------------|
| Laravel | Latest | [laravel/laravel](https://github.com/laravel/laravel) | ~50MB |
| Symfony | Latest | [symfony/symfony-demo](https://github.com/symfony/symfony-demo) | ~30MB |
| CodeIgniter | 4.x | [codeigniter4/CodeIgniter4](https://github.com/codeigniter4/CodeIgniter4) | ~20MB |
| CakePHP | Latest | [cakephp/app](https://github.com/cakephp/app) | ~25MB |
| Yii | 2.x | [yiisoft/yii2-app-basic](https://github.com/yiisoft/yii2-app-basic) | ~15MB |

## Notes

- All frameworks are downloaded with `--depth 1` to minimize size (shallow clone)
- Framework source code is used for static analysis and pattern matching
- No framework dependencies need to be installed for the HNP scanner
- Each framework directory should contain the complete source code structure

## Troubleshooting

If you encounter issues downloading frameworks:

1. **Git not found**: Install git first
   ```bash
   sudo apt-get install git  # Ubuntu/Debian
   brew install git          # macOS
   ```

2. **Network issues**: Try using SSH instead of HTTPS
   ```bash
   git clone --depth 1 git@github.com:laravel/laravel.git laravel
   ```

3. **Permission issues**: Ensure you have write permissions in this directory
   ```bash
   chmod 755 .
   ```

4. **Update existing frameworks**: Use the CLI tool's update feature
   ```bash
   python3 ../src/framework_cli.py --download 1  # Will update if exists
   ```
