head -n 1 /dataset/downloaded_artifacts/cve_2001/cve_2001.csv >> /dataset/cve_combined.csv          
tail -n +2 -q /dataset/downloaded_artifacts/cve_*/cve_*.csv >> /dataset/cve_combined.csv