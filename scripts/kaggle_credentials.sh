cd ..
mkdir -p ~/.kaggle
echo {"name": "$KAGGLE_USERNAME", "key": "$KAGGLE_KEY"} >>  ~/.kaggle/kaggle.json
#Setting to r+w 
chmod 600 ~/.kaggle/kaggle.json

cd scripts
