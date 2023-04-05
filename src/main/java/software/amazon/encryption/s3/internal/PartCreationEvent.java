// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import java.io.File;

public class PartCreationEvent {
    private final File part;
    private final int partNumber;
    private final boolean isLastPart;
    private final OnFileDelete fileDeleteObserver;

    PartCreationEvent(File part, int partNumber, boolean isLastPart,
                      OnFileDelete fileDeleteObserver) {
        if (part == null) {
            throw new IllegalArgumentException("part must not be specified");
        }
        this.part = part;
        this.partNumber = partNumber;
        this.isLastPart = isLastPart;
        this.fileDeleteObserver = fileDeleteObserver;
    }

    /**
     * Returns a non-null part (in the form of a file) for multipart upload.
     */
    public File getPart() {
        return part;
    }

    public int getPartNumber() {
        return partNumber;
    }

    public boolean isLastPart() {
        return isLastPart;
    }

    /**
     * Returns an observer for file deletion; or null if there is none.
     */
    public OnFileDelete getFileDeleteObserver() {
        return fileDeleteObserver;
    }
}
