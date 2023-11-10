// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.internal.MultiFileOutputStream;
import software.amazon.encryption.s3.internal.UploadObjectObserver;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MultipartConfiguration {
    private final long _partSize;
    private final int _maxConnections;
    private final long _diskLimit;
    private final UploadObjectObserver _observer;
    private final ExecutorService _es;
    private final boolean _usingDefaultExecutorService;
    private final MultiFileOutputStream _outputStream;

    public MultipartConfiguration(Builder builder) {
        this._maxConnections = builder._maxConnections;
        this._partSize = builder._partSize;
        this._diskLimit = builder._diskLimit;
        this._observer = builder._observer;
        this._es = builder._es;
        this._usingDefaultExecutorService = builder._usingDefaultExecutorService;
        this._outputStream = builder._outputStream;
    }

    static public Builder builder() {
        return new Builder();
    }

    public int maxConnections() {
        return _maxConnections;
    }

    public long partSize() {
        return _partSize;
    }

    public long diskLimit() {
        return _diskLimit;
    }

    public MultiFileOutputStream multiFileOutputStream() {
        return _outputStream;
    }

    public UploadObjectObserver uploadObjectObserver() {
        return _observer;
    }

    public ExecutorService executorService() {
        return _es;
    }

    public boolean usingDefaultExecutorService() {
        return _usingDefaultExecutorService;
    }

    static public class Builder {
        private final long MIN_PART_SIZE = 5 << 20;
        private MultiFileOutputStream _outputStream = new MultiFileOutputStream();
        // Default Max Connections is 50
        private int _maxConnections = 50;
        // Set Min Allowed Part Size as Default
        private long _partSize = MIN_PART_SIZE;
        private long _diskLimit = Long.MAX_VALUE;
        private UploadObjectObserver _observer = new UploadObjectObserver();
        // If null, ExecutorService will be initialized in build() based on maxConnections.
        private ExecutorService _es = null;
        private boolean _usingDefaultExecutorService;

        private Builder() {
        }

        public Builder maxConnections(int maxConnections) {
            _maxConnections = maxConnections;
            return this;
        }

        public Builder partSize(long partSize) {
            if (partSize < MIN_PART_SIZE)
                throw new IllegalArgumentException("partSize must be at least "
                        + MIN_PART_SIZE);
            _partSize = partSize;
            return this;
        }

        public Builder diskLimit(long diskLimit) {
            _diskLimit = diskLimit;
            return this;
        }

        public Builder uploadObjectObserver(UploadObjectObserver observer) {
            _observer = observer;
            return this;
        }

        public Builder executorService(ExecutorService es) {
            _es = es;
            return this;
        }

        public Builder multiFileOutputStream(MultiFileOutputStream outputStream) {
            _outputStream = outputStream;
            return this;
        }

        public MultipartConfiguration build() {
            if (_es == null) {
                _es = Executors.newFixedThreadPool(_maxConnections);
                _usingDefaultExecutorService = true;
            } else {
                _usingDefaultExecutorService = false;
            }

            return new MultipartConfiguration(this);
        }
    }
}
