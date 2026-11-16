# Scoring image plus the trained detector's runtime. The detector itself (attesta_DL
# code, configs, one checkpoint) is mounted read-only by docker-compose.dl.yml, not copied.
# Versions match the environment the checkpoint was trained in (CPU build of torch).
FROM attesta-spire-gateway:local

USER root
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.5.1 \
    && pip install numpy==2.5.4 pandas==3.1.0 requests==2.34.2 pyzipper==0.4.0 \
       esprima==4.0.1 rapidfuzz==3.14.6
USER 1002
