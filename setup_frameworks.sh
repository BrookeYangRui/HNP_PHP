#!/bin/bash

# Framework Setup Script for HNP Analysis
# This script helps download and setup PHP frameworks for analysis

echo "🔧 HNP Framework Setup Tool"
echo "============================"

# Set PHP 8.3 environment
export PATH="/usr/local/php8.3/bin:$PATH"

# Check if composer is available
if ! command -v composer &> /dev/null; then
    echo "❌ Composer not found. Please install Composer first."
    echo "Visit: https://getcomposer.org/download/"
    exit 1
fi

# Create frameworks directory if it doesn't exist
mkdir -p frameworks
cd frameworks

echo "📁 Available framework downloads:"
echo "1. Laravel (Latest)"
echo "2. Symfony (Latest)"
echo "3. WordPress (Latest)"
echo "4. CodeIgniter 4 (Latest)"
echo "5. CakePHP (Latest)"
echo "6. Yii2 (Latest)"
echo "7. Download All"
echo "0. Exit"
echo ""

read -p "Select framework to download (0-7): " choice

case $choice in
    1)
        echo "📦 Downloading Laravel..."
        composer create-project laravel/laravel:^10.0 laravel --no-interaction
        echo "✅ Laravel downloaded to frameworks/laravel/"
        ;;
    2)
        echo "📦 Downloading Symfony..."
        composer create-project symfony/skeleton:^6.0 symfony --no-interaction
        echo "✅ Symfony downloaded to frameworks/symfony/"
        ;;
    3)
        echo "📦 Downloading WordPress..."
        wget -O wordpress.zip https://wordpress.org/latest.zip
        unzip wordpress.zip
        mv wordpress wordpress
        rm wordpress.zip
        echo "✅ WordPress downloaded to frameworks/wordpress/"
        ;;
    4)
        echo "📦 Downloading CodeIgniter 4..."
        composer create-project codeigniter4/appstarter codeigniter --no-interaction
        echo "✅ CodeIgniter 4 downloaded to frameworks/codeigniter/"
        ;;
    5)
        echo "📦 Downloading CakePHP..."
        composer create-project cakephp/app cakephp --no-interaction
        echo "✅ CakePHP downloaded to frameworks/cakephp/"
        ;;
    6)
        echo "📦 Downloading Yii2..."
        composer create-project --prefer-dist yiisoft/yii2-app-basic yii --no-interaction
        echo "✅ Yii2 downloaded to frameworks/yii/"
        ;;
    7)
        echo "📦 Downloading all frameworks..."
        echo "This may take a while..."
        
        echo "  - Laravel..."
        composer create-project laravel/laravel:^10.0 laravel --no-interaction
        
        echo "  - Symfony..."
        composer create-project symfony/skeleton:^6.0 symfony --no-interaction
        
        echo "  - WordPress..."
        wget -O wordpress.zip https://wordpress.org/latest.zip
        unzip wordpress.zip
        mv wordpress wordpress
        rm wordpress.zip
        
        echo "  - CodeIgniter 4..."
        composer create-project codeigniter4/appstarter codeigniter --no-interaction
        
        echo "  - CakePHP..."
        composer create-project cakephp/app cakephp --no-interaction
        
        echo "  - Yii2..."
        composer create-project --prefer-dist yiisoft/yii2-app-basic yii --no-interaction
        
        echo "✅ All frameworks downloaded!"
        ;;
    0)
        echo "👋 Goodbye!"
        exit 0
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "🎉 Framework setup completed!"
echo "You can now run the interactive analyzer:"
echo "  ./run_interactive.sh"
