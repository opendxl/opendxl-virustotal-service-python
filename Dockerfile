# Base image from Python 2.7 (slim)
FROM python:2.7-slim

VOLUME ["/opt/dxlvtapiservice-config"]

# Install required packages
RUN pip install "requests"
RUN pip install "dxlbootstrap"
RUN pip install "dxlclient"

# Copy service files
COPY . /tmp/build
WORKDIR /tmp/build

# Clean service
RUN python ./clean.py

# Build service
RUN python ./setup.py bdist_wheel

# Install service
RUN pip install dist/*.whl

# Cleanup build
RUN rm -rf /tmp/build

################### INSTALLATION END #######################
#
# Run the service.
#
# NOTE: The configuration files for the service must be
#       mapped to the path: /opt/dxlvtapiservice-config
#
# For example, specify a "-v" argument to the run command
# to mount a directory on the host as a data volume:
#
#   -v /host/dir/to/config:/opt/dxlvtapiservice-config
#
CMD ["python", "-m", "dxlvtapiservice", "/opt/dxlvtapiservice-config"]
