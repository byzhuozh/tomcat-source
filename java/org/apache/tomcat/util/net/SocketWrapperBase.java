/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock.WriteLock;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

public abstract class SocketWrapperBase<E> {

    private static final Log log = LogFactory.getLog(SocketWrapperBase.class);

    protected static final StringManager sm = StringManager.getManager(SocketWrapperBase.class);

    private final E socket;
    private final AbstractEndpoint<E> endpoint;

    // Volatile because I/O and setting the timeout values occurs on a different
    // thread to the thread checking the timeout.
    private volatile long readTimeout = -1;
    private volatile long writeTimeout = -1;

    private volatile int keepAliveLeft = 100;
    private volatile boolean upgraded = false;
    private boolean secure = false;
    private String negotiatedProtocol = null;
    /*
     * Following cached for speed / reduced GC
     */
    protected String localAddr = null;
    protected String localName = null;
    protected int localPort = -1;
    protected String remoteAddr = null;
    protected String remoteHost = null;
    protected int remotePort = -1;
    /*
     * Used if block/non-blocking is set at the socket level. The client is
     * responsible for the thread-safe use of this field via the locks provided.
     */
    private volatile boolean blockingStatus = true;
    private final Lock blockingStatusReadLock;
    private final WriteLock blockingStatusWriteLock;
    /*
     * Used to record the first IOException that occurs during non-blocking
     * read/writes that can't be usefully propagated up the stack since there is
     * no user code or appropriate container code in the stack to handle it.
     */
    private volatile IOException error = null;

    /**
     * The buffers used for communicating with the socket.
     */
    protected volatile SocketBufferHandler socketBufferHandler = null;

    /**
     * The max size of the individual buffered write buffers
     */
    protected int bufferedWriteSize = 64 * 1024; // 64k default write buffer

    /**
     * Additional buffer used for non-blocking writes. Non-blocking writes need
     * to return immediately even if the data cannot be written immediately but
     * the socket buffer may not be big enough to hold all of the unwritten
     * data. This structure provides an additional buffer to hold the data until
     * it can be written.
     * Not that while the Servlet API only allows one non-blocking write at a
     * time, due to buffering and the possible need to write HTTP headers, this
     * layer may see multiple writes.
     */
    protected final WriteBuffer nonBlockingWriteBuffer = new WriteBuffer(bufferedWriteSize);

    public SocketWrapperBase(E socket, AbstractEndpoint<E> endpoint) {
        this.socket = socket;
        this.endpoint = endpoint;
        ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
        this.blockingStatusReadLock = lock.readLock();
        this.blockingStatusWriteLock = lock.writeLock();
    }

    public E getSocket() {
        return socket;
    }

    public AbstractEndpoint<E> getEndpoint() {
        return endpoint;
    }

    public IOException getError() { return error; }
    public void setError(IOException error) {
        // Not perfectly thread-safe but good enough. Just needs to ensure that
        // once this.error is non-null, it can never be null.
        if (this.error != null) {
            return;
        }
        this.error = error;
    }
    public void checkError() throws IOException {
        if (error != null) {
            throw error;
        }
    }

    public boolean isUpgraded() { return upgraded; }
    public void setUpgraded(boolean upgraded) { this.upgraded = upgraded; }
    public boolean isSecure() { return secure; }
    public void setSecure(boolean secure) { this.secure = secure; }
    public String getNegotiatedProtocol() { return negotiatedProtocol; }
    public void setNegotiatedProtocol(String negotiatedProtocol) {
        this.negotiatedProtocol = negotiatedProtocol;
    }

    /**
     * Set the timeout for reading. Values of zero or less will be changed to
     * -1.
     *
     * @param readTimeout The timeout in milliseconds. A value of -1 indicates
     *                    an infinite timeout.
     */
    public void setReadTimeout(long readTimeout) {
        if (readTimeout > 0) {
            this.readTimeout = readTimeout;
        } else {
            this.readTimeout = -1;
        }
    }

    public long getReadTimeout() {
        return this.readTimeout;
    }

    /**
     * Set the timeout for writing. Values of zero or less will be changed to
     * -1.
     *
     * @param writeTimeout The timeout in milliseconds. A value of zero or less
     *                    indicates an infinite timeout.
     */
    public void setWriteTimeout(long writeTimeout) {
        if (writeTimeout > 0) {
            this.writeTimeout = writeTimeout;
        } else {
            this.writeTimeout = -1;
        }
    }

    public long getWriteTimeout() {
        return this.writeTimeout;
    }


    public void setKeepAliveLeft(int keepAliveLeft) { this.keepAliveLeft = keepAliveLeft;}
    public int decrementKeepAlive() { return (--keepAliveLeft);}

    public String getRemoteHost() {
        if (remoteHost == null) {
            populateRemoteHost();
        }
        return remoteHost;
    }
    protected abstract void populateRemoteHost();

    public String getRemoteAddr() {
        if (remoteAddr == null) {
            populateRemoteAddr();
        }
        return remoteAddr;
    }
    protected abstract void populateRemoteAddr();

    public int getRemotePort() {
        if (remotePort == -1) {
            populateRemotePort();
        }
        return remotePort;
    }
    protected abstract void populateRemotePort();

    public String getLocalName() {
        if (localName == null) {
            populateLocalName();
        }
        return localName;
    }
    protected abstract void populateLocalName();

    public String getLocalAddr() {
        if (localAddr == null) {
            populateLocalAddr();
        }
        return localAddr;
    }
    protected abstract void populateLocalAddr();

    public int getLocalPort() {
        if (localPort == -1) {
            populateLocalPort();
        }
        return localPort;
    }
    protected abstract void populateLocalPort();

    public boolean getBlockingStatus() { return blockingStatus; }
    public void setBlockingStatus(boolean blockingStatus) {
        this.blockingStatus = blockingStatus;
    }
    public Lock getBlockingStatusReadLock() { return blockingStatusReadLock; }
    public WriteLock getBlockingStatusWriteLock() {
        return blockingStatusWriteLock;
    }
    public SocketBufferHandler getSocketBufferHandler() { return socketBufferHandler; }

    public boolean hasDataToRead() {
        // Return true because it is always safe to make a read attempt
        return true;
    }

    public boolean hasDataToWrite() {
        return !socketBufferHandler.isWriteBufferEmpty() || !nonBlockingWriteBuffer.isEmpty();
    }

    /**
     * Checks to see if there are any writes pending and if there are calls
     * {@link #registerWriteInterest()} to trigger a callback once the pending
     * writes have completed.
     * <p>
     * Note: Once this method has returned <code>false</code> it <b>MUST NOT</b>
     *       be called again until the pending write has completed and the
     *       callback has been fired.
     *       TODO: Modify {@link #registerWriteInterest()} so the above
     *       restriction is enforced there rather than relying on the caller.
     *
     * @return <code>true</code> if no writes are pending and data can be
     *         written otherwise <code>false</code>
     */
    public boolean isReadyForWrite() {
        boolean result = canWrite();
        if (!result) {
            registerWriteInterest();
        }
        return result;
    }


    public boolean canWrite() {
        if (socketBufferHandler == null) {
            throw new IllegalStateException(sm.getString("socket.closed"));
        }
        return socketBufferHandler.isWriteBufferWritable() && nonBlockingWriteBuffer.isEmpty();
    }


    /**
     * Overridden for debug purposes. No guarantees are made about the format of
     * this message which may vary significantly between point releases.
     * <p>
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return super.toString() + ":" + String.valueOf(socket);
    }


    public abstract int read(boolean block, byte[] b, int off, int len) throws IOException;
    public abstract int read(boolean block, ByteBuffer to) throws IOException;
    public abstract boolean isReadyForRead() throws IOException;
    public abstract void setAppReadBufHandler(ApplicationBufferHandler handler);

    protected int populateReadBuffer(byte[] b, int off, int len) {
        socketBufferHandler.configureReadBufferForRead();
        ByteBuffer readBuffer = socketBufferHandler.getReadBuffer();
        int remaining = readBuffer.remaining();

        // Is there enough data in the read buffer to satisfy this request?
        // Copy what data there is in the read buffer to the byte array
        if (remaining > 0) {
            remaining = Math.min(remaining, len);
            readBuffer.get(b, off, remaining);

            if (log.isDebugEnabled()) {
                log.debug("Socket: [" + this + "], Read from buffer: [" + remaining + "]");
            }
        }
        return remaining;
    }


    protected int populateReadBuffer(ByteBuffer to) {
        // Is there enough data in the read buffer to satisfy this request?
        // Copy what data there is in the read buffer to the byte array
        socketBufferHandler.configureReadBufferForRead();
        int nRead = transfer(socketBufferHandler.getReadBuffer(), to);

        if (log.isDebugEnabled()) {
            log.debug("Socket: [" + this + "], Read from buffer: [" + nRead + "]");
        }
        return nRead;
    }


    /**
     * Return input that has been read to the input buffer for re-reading by the
     * correct component. There are times when a component may read more data
     * than it needs before it passes control to another component. One example
     * of this is during HTTP upgrade. If an (arguably misbehaving client) sends
     * data associated with the upgraded protocol before the HTTP upgrade
     * completes, the HTTP handler may read it. This method provides a way for
     * that data to be returned so it can be processed by the correct component.
     *
     * @param returnedInput The input to return to the input buffer.
     */
    public void unRead(ByteBuffer returnedInput) {
        if (returnedInput != null) {
            socketBufferHandler.configureReadBufferForWrite();
            socketBufferHandler.getReadBuffer().put(returnedInput);
        }
    }


    public abstract void close() throws IOException;
    public abstract boolean isClosed();


    /**
     * Writes the provided data to the socket write buffer. If the socket write
     * buffer fills during the write, the content of the socket write buffer is
     * written to the network and this method starts to fill the socket write
     * buffer again. Depending on the size of the data to write, there may be
     * multiple writes to the network.
     * <p>
     * Non-blocking writes must return immediately and the byte array holding
     * the data to be written must be immediately available for re-use. It may
     * not be possible to write sufficient data to the network to allow this to
     * happen. In this case data that cannot be written to the network and
     * cannot be held by the socket buffer is stored in the non-blocking write
     * buffer.
     * <p>
     * Note: There is an implementation assumption that, before switching from
     *       non-blocking writes to blocking writes, any data remaining in the
     *       non-blocking write buffer will have been written to the network.
     *
     * @param block <code>true</code> if a blocking write should be used,
     *                  otherwise a non-blocking write will be used
     * @param buf   The byte array containing the data to be written
     * @param off   The offset within the byte array of the data to be written
     * @param len   The length of the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    public final void write(boolean block, byte[] buf, int off, int len) throws IOException {
        if (len == 0 || buf == null) {
            return;
        }

        /*
         * While the implementations for blocking and non-blocking writes are
         * very similar they have been split into separate methods:
         * - To allow sub-classes to override them individually. NIO2, for
         *   example, overrides the non-blocking write but not the blocking
         *   write.
         * - To enable a marginally more efficient implemented for blocking
         *   writes which do not require the additional checks related to the
         *   use of the non-blocking write buffer
         *   TODO: Explore re-factoring options to remove the split into
         *         separate methods
         */
        if (block) {
            writeBlocking(buf, off, len);
        } else {
            writeNonBlocking(buf, off, len);
        }
    }


    /**
     * Writes the provided data to the socket write buffer. If the socket write
     * buffer fills during the write, the content of the socket write buffer is
     * written to the network and this method starts to fill the socket write
     * buffer again. Depending on the size of the data to write, there may be
     * multiple writes to the network.
     * <p>
     * Non-blocking writes must return immediately and the ByteBuffer holding
     * the data to be written must be immediately available for re-use. It may
     * not be possible to write sufficient data to the network to allow this to
     * happen. In this case data that cannot be written to the network and
     * cannot be held by the socket buffer is stored in the non-blocking write
     * buffer.
     * <p>
     * Note: There is an implementation assumption that, before switching from
     *       non-blocking writes to blocking writes, any data remaining in the
     *       non-blocking write buffer will have been written to the network.
     *
     * @param block  <code>true</code> if a blocking write should be used,
     *               otherwise a non-blocking write will be used
     * @param from   The ByteBuffer containing the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    public final void write(boolean block, ByteBuffer from) throws IOException {
        if (from == null || from.remaining() == 0) {
            return;
        }

        /*
         * While the implementations for blocking and non-blocking writes are
         * very similar they have been split into separate methods:
         * - To allow sub-classes to override them individually. NIO2, for
         *   example, overrides the non-blocking write but not the blocking
         *   write.
         * - To enable a marginally more efficient implemented for blocking
         *   writes which do not require the additional checks related to the
         *   use of the non-blocking write buffer
         *   TODO: Explore re-factoring options to remove the split into
         *         separate methods
         */
        if (block) {
            writeBlocking(from);
        } else {
            writeNonBlocking(from);
        }
    }


    /**
     * Writes the provided data to the socket write buffer. If the socket write
     * buffer fills during the write, the content of the socket write buffer is
     * written to the network using a blocking write. Once that blocking write
     * is complete, this method starts to fill the socket write buffer again.
     * Depending on the size of the data to write, there may be multiple writes
     * to the network. On completion of this method there will always be space
     * remaining in the socket write buffer.
     *
     * @param buf   The byte array containing the data to be written
     * @param off   The offset within the byte array of the data to be written
     * @param len   The length of the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    protected void writeBlocking(byte[] buf, int off, int len) throws IOException {
        socketBufferHandler.configureWriteBufferForWrite();
        int thisTime = transfer(buf, off, len, socketBufferHandler.getWriteBuffer());
        while (socketBufferHandler.getWriteBuffer().remaining() == 0) {
            len = len - thisTime;
            off = off + thisTime;
            doWrite(true);
            socketBufferHandler.configureWriteBufferForWrite();
            thisTime = transfer(buf, off, len, socketBufferHandler.getWriteBuffer());
        }
    }


    /**
     * Writes the provided data to the socket write buffer. If the socket write
     * buffer fills during the write, the content of the socket write buffer is
     * written to the network using a blocking write. Once that blocking write
     * is complete, this method starts to fill the socket write buffer again.
     * Depending on the size of the data to write, there may be multiple writes
     * to the network. On completion of this method there will always be space
     * remaining in the socket write buffer.
     *
     * @param from The ByteBuffer containing the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    protected void writeBlocking(ByteBuffer from) throws IOException {
        if (socketBufferHandler.isWriteBufferEmpty()) {
            //header部分数据时，socket的write buffer是空的，是直接写
            // Socket write buffer is empty. Write the provided buffer directly
            // to the network.
            // TODO Shouldn't smaller writes be buffered anyway?
            //其实这里并不一定直接发，还会检查发送的数据大小和socket write buffer大小比较，
            //如果小于还是先写到socket write buffer,这样减少系统调用，保证一次写系统调用尽量写足够多的数据，如果大于则先把from的write buffer的大小的数据写到os层，剩余的写到write buffer
            writeBlockingDirect(from);
        } else {
            //写body部分时，是找这里，因为socket的writeBuffer有header的数据
            // Socket write buffer has some data.
            socketBufferHandler.configureWriteBufferForWrite();
            // Put as much data as possible into the write buffer
            transfer(from, socketBufferHandler.getWriteBuffer());
            // If the buffer is now full, write it to the network and then write
            // the remaining data directly to the network.
            if (!socketBufferHandler.isWriteBufferWritable()) {
                //如果socket的writeBuffer写满了，则把数据写到os层
                doWrite(true);
                writeBlockingDirect(from);
            }
        }
    }


    /**
     * Writes directly to the network, bypassing the socket write buffer.
     *
     * @param from The ByteBuffer containing the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    protected void writeBlockingDirect(ByteBuffer from) throws IOException {
        // The socket write buffer capacity is socket.appWriteBufSize
        // TODO This only matters when using TLS. For non-TLS connections it
        //      should be possible to write the ByteBuffer in a single write
        int limit = socketBufferHandler.getWriteBuffer().capacity();
        int fromLimit = from.limit();
        while (from.remaining() >= limit) {
            from.limit(from.position() + limit);
            doWrite(true, from);
            from.limit(fromLimit);
        }

        if (from.remaining() > 0) {
            socketBufferHandler.configureWriteBufferForWrite();
            transfer(from, socketBufferHandler.getWriteBuffer());
        }
    }


    /**
     * Transfers the data to the socket write buffer (writing that data to the
     * socket if the buffer fills up using a non-blocking write) until either
     * all the data has been transferred and space remains in the socket write
     * buffer or a non-blocking write leaves data in the socket write buffer.
     * After an incomplete write, any data remaining to be transferred to the
     * socket write buffer will be copied to the socket write buffer. If the
     * remaining data is too big for the socket write buffer, the socket write
     * buffer will be filled and the additional data written to the non-blocking
     * write buffer.
     *
     * @param buf   The byte array containing the data to be written
     * @param off   The offset within the byte array of the data to be written
     * @param len   The length of the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    protected void writeNonBlocking(byte[] buf, int off, int len) throws IOException {
        if (nonBlockingWriteBuffer.isEmpty() && socketBufferHandler.isWriteBufferWritable()) {
            socketBufferHandler.configureWriteBufferForWrite();
            int thisTime = transfer(buf, off, len, socketBufferHandler.getWriteBuffer());
            len = len - thisTime;
            while (!socketBufferHandler.isWriteBufferWritable()) {
                off = off + thisTime;
                doWrite(false);
                if (len > 0 && socketBufferHandler.isWriteBufferWritable()) {
                    socketBufferHandler.configureWriteBufferForWrite();
                    thisTime = transfer(buf, off, len, socketBufferHandler.getWriteBuffer());
                } else {
                    // Didn't write any data in the last non-blocking write.
                    // Therefore the write buffer will still be full. Nothing
                    // else to do here. Exit the loop.
                    break;
                }
                len = len - thisTime;
            }
        }

        if (len > 0) {
            // Remaining data must be buffered
            nonBlockingWriteBuffer.add(buf, off, len);
        }
    }


    /**
     * Transfers the data to the socket write buffer (writing that data to the
     * socket if the buffer fills up using a non-blocking write) until either
     * all the data has been transferred and space remains in the socket write
     * buffer or a non-blocking write leaves data in the socket write buffer.
     * After an incomplete write, any data remaining to be transferred to the
     * socket write buffer will be copied to the socket write buffer. If the
     * remaining data is too big for the socket write buffer, the socket write
     * buffer will be filled and the additional data written to the non-blocking
     * write buffer.
     *
     * @param from The ByteBuffer containing the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    protected void writeNonBlocking(ByteBuffer from)
            throws IOException {

        if (nonBlockingWriteBuffer.isEmpty() && socketBufferHandler.isWriteBufferWritable()) {
            writeNonBlockingInternal(from);
        }

        if (from.remaining() > 0) {
            // Remaining data must be buffered
            nonBlockingWriteBuffer.add(from);
        }
    }


    /**
     * Separate method so it can be re-used by the socket write buffer to write
     * data to the network
     *
     * @param from The ByteBuffer containing the data to be written
     *
     * @throws IOException If an IO error occurs during the write
     */
    protected void writeNonBlockingInternal(ByteBuffer from) throws IOException {
        if (socketBufferHandler.isWriteBufferEmpty()) {
            writeNonBlockingDirect(from);
        } else {
            socketBufferHandler.configureWriteBufferForWrite();
            transfer(from, socketBufferHandler.getWriteBuffer());
            if (!socketBufferHandler.isWriteBufferWritable()) {
                doWrite(false);
                if (socketBufferHandler.isWriteBufferWritable()) {
                    writeNonBlockingDirect(from);
                }
            }
        }
    }


    protected void writeNonBlockingDirect(ByteBuffer from) throws IOException {
        // The socket write buffer capacity is socket.appWriteBufSize
        // TODO This only matters when using TLS. For non-TLS connections it
        //      should be possible to write the ByteBuffer in a single write
        int limit = socketBufferHandler.getWriteBuffer().capacity();
        int fromLimit = from.limit();
        while (from.remaining() >= limit) {
            int newLimit = from.position() + limit;
            from.limit(newLimit);
            doWrite(false, from);
            from.limit(fromLimit);
            if (from.position() != newLimit) {
                // Didn't write the whole amount of data in the last
                // non-blocking write.
                // Exit the loop.
                return;
            }
        }

        if (from.remaining() > 0) {
            socketBufferHandler.configureWriteBufferForWrite();
            transfer(from, socketBufferHandler.getWriteBuffer());
        }
    }


    /**
     * Writes as much data as possible from any that remains in the buffers.
     *
     * @param block <code>true</code> if a blocking write should be used,
     *                  otherwise a non-blocking write will be used
     *
     * @return <code>true</code> if data remains to be flushed after this method
     *         completes, otherwise <code>false</code>. In blocking mode
     *         therefore, the return value should always be <code>false</code>
     *
     * @throws IOException If an IO error occurs during the write
     */
    public boolean flush(boolean block) throws IOException {
        boolean result = false;
        if (block) {
            // A blocking flush will always empty the buffer.
            flushBlocking();
        } else {
            result = flushNonBlocking();
        }

        return result;
    }


    protected void flushBlocking() throws IOException {
        doWrite(true);

        if (!nonBlockingWriteBuffer.isEmpty()) {
            nonBlockingWriteBuffer.write(this, true);

            if (!socketBufferHandler.isWriteBufferEmpty()) {
                doWrite(true);
            }
        }

    }


    protected boolean flushNonBlocking() throws IOException {
        boolean dataLeft = !socketBufferHandler.isWriteBufferEmpty();

        // Write to the socket, if there is anything to write
        if (dataLeft) {
            doWrite(false);
            dataLeft = !socketBufferHandler.isWriteBufferEmpty();
        }

        if (!dataLeft && !nonBlockingWriteBuffer.isEmpty()) {
            dataLeft = nonBlockingWriteBuffer.write(this, false);

            if (!dataLeft && !socketBufferHandler.isWriteBufferEmpty()) {
                doWrite(false);
                dataLeft = !socketBufferHandler.isWriteBufferEmpty();
            }
        }

        return dataLeft;
    }


    /**
     * Write the contents of the socketWriteBuffer to the socket. For blocking
     * writes either then entire contents of the buffer will be written or an
     * IOException will be thrown. Partial blocking writes will not occur.
     *
     * @param block Should the write be blocking or not?
     *
     * @throws IOException If an I/O error such as a timeout occurs during the
     *                     write
     */
    protected void doWrite(boolean block) throws IOException {
        socketBufferHandler.configureWriteBufferForRead();
        doWrite(block, socketBufferHandler.getWriteBuffer());
    }


    /**
     * Write the contents of the ByteBuffer to the socket. For blocking writes
     * either then entire contents of the buffer will be written or an
     * IOException will be thrown. Partial blocking writes will not occur.
     *
     * @param block Should the write be blocking or not?
     * @param from the ByteBuffer containing the data to be written
     *
     * @throws IOException If an I/O error such as a timeout occurs during the
     *                     write
     */
    protected abstract void doWrite(boolean block, ByteBuffer from) throws IOException;


    public void processSocket(SocketEvent socketStatus, boolean dispatch) {
        endpoint.processSocket(this, socketStatus, dispatch);
    }


    public abstract void registerReadInterest();

    public abstract void registerWriteInterest();

    public abstract SendfileDataBase createSendfileData(String filename, long pos, long length);

    /**
     * Starts the sendfile process. It is expected that if the sendfile process
     * does not complete during this call and does not report an error, that the
     * caller <b>will not</b> add the socket to the poller (or equivalent). That
     * is the responsibility of this method.
     *
     * @param sendfileData Data representing the file to send
     *
     * @return The state of the sendfile process after the first write.
     */
    public abstract SendfileState processSendfile(SendfileDataBase sendfileData);

    /**
     * Require the client to perform CLIENT-CERT authentication if it hasn't
     * already done so.
     *
     * @param sslSupport The SSL/TLS support instance currently being used by
     *                   the connection that may need updating after the client
     *                   authentication
     *
     * @throws IOException If authentication is required then there will be I/O
     *                     with the client and this exception will be thrown if
     *                     that goes wrong
     */
    public abstract void doClientAuth(SSLSupport sslSupport) throws IOException;

    public abstract SSLSupport getSslSupport(String clientCertProvider);


    // ------------------------------------------------------- NIO 2 style APIs


    public enum BlockingMode {
        /**
         * The operation will now block. If there are pending operations,
         * the operation will return CompletionState.NOT_DONE.
         */
        NON_BLOCK,
        /**
         * The operation will block until pending operations are completed, but
         * will not block after performing it.
         */
        SEMI_BLOCK,
        /**
         * The operation will block until completed.
         */
        BLOCK
    }

    public enum CompletionState {
        /**
         * Operation is still pending.
         */
        PENDING,
        /**
         * Operation was pending and non blocking.
         */
        NOT_DONE,
        /**
         * The operation completed inline.
         */
        INLINE,
        /**
         * The operation completed inline but failed.
         */
        ERROR,
        /**
         * The operation completed, but not inline.
         */
        DONE
    }

    public enum CompletionHandlerCall {
        /**
         * Operation should continue, the completion handler shouldn't be
         * called.
         */
        CONTINUE,
        /**
         * The operation completed but the completion handler shouldn't be
         * called.
         */
        NONE,
        /**
         * The operation is complete, the completion handler should be
         * called.
         */
        DONE
    }

    public interface CompletionCheck {
        /**
         * Determine what call, if any, should be made to the completion
         * handler.
         *
         * @param state of the operation (done or done in-line since the
         *        IO call is done)
         * @param buffers ByteBuffer[] that has been passed to the
         *        original IO call
         * @param offset that has been passed to the original IO call
         * @param length that has been passed to the original IO call
         *
         * @return The call, if any, to make to the completion handler
         */
        public CompletionHandlerCall callHandler(CompletionState state, ByteBuffer[] buffers,
                int offset, int length);
    }

    /**
     * This utility CompletionCheck will cause the write to fully write
     * all remaining data. If the operation completes inline, the
     * completion handler will not be called.
     */
    public static final CompletionCheck COMPLETE_WRITE = new CompletionCheck() {
        @Override
        public CompletionHandlerCall callHandler(CompletionState state, ByteBuffer[] buffers,
                int offset, int length) {
            for (int i = 0; i < length; i++) {
                if (buffers[offset + i].remaining() > 0) {
                    return CompletionHandlerCall.CONTINUE;
                }
            }
            return (state == CompletionState.DONE) ? CompletionHandlerCall.DONE
                    : CompletionHandlerCall.NONE;
        }
    };

    /**
     * This utility CompletionCheck will cause the write to fully write
     * all remaining data. The completion handler will then be called.
     */
    public static final CompletionCheck COMPLETE_WRITE_WITH_COMPLETION = new CompletionCheck() {
        @Override
        public CompletionHandlerCall callHandler(CompletionState state, ByteBuffer[] buffers,
                int offset, int length) {
            for (int i = 0; i < length; i++) {
                if (buffers[offset + i].remaining() > 0) {
                    return CompletionHandlerCall.CONTINUE;
                }
            }
            return CompletionHandlerCall.DONE;
        }
    };

    /**
     * This utility CompletionCheck will cause the completion handler
     * to be called once some data has been read. If the operation
     * completes inline, the completion handler will not be called.
     */
    public static final CompletionCheck READ_DATA = new CompletionCheck() {
        @Override
        public CompletionHandlerCall callHandler(CompletionState state, ByteBuffer[] buffers,
                int offset, int length) {
            return (state == CompletionState.DONE) ? CompletionHandlerCall.DONE
                    : CompletionHandlerCall.NONE;
        }
    };

    /**
     * Allows using NIO2 style read/write only for connectors that can
     * efficiently support it.
     *
     * @return This default implementation always returns {@code false}
     */
    public boolean hasAsyncIO() {
        return false;
    }

    /**
     * Allows checking if an asynchronous read operation is currently pending.
     * @return <code>true</code> if the endpoint supports asynchronous IO and
     *  a read operation is being processed asynchronously
     */
    public boolean isReadPending() {
        return false;
    }

    /**
     * Allows checking if an asynchronous write operation is currently pending.
     * @return <code>true</code> if the endpoint supports asynchronous IO and
     *  a write operation is being processed asynchronously
     */
    public boolean isWritePending() {
        return false;
    }

    /**
     * If an asynchronous read operation is pending, this method will block
     * until the operation completes, or the specified amount of time
     * has passed.
     * @param timeout The maximum amount of time to wait
     * @param unit The unit for the timeout
     * @return <code>true</code> if the read operation is complete,
     *  <code>false</code> if the operation is still pending and
     *  the specified timeout has passed
     */
    @Deprecated
    public boolean awaitReadComplete(long timeout, TimeUnit unit) {
        return true;
    }

    /**
     * If an asynchronous write operation is pending, this method will block
     * until the operation completes, or the specified amount of time
     * has passed.
     * @param timeout The maximum amount of time to wait
     * @param unit The unit for the timeout
     * @return <code>true</code> if the read operation is complete,
     *  <code>false</code> if the operation is still pending and
     *  the specified timeout has passed
     */
    @Deprecated
    public boolean awaitWriteComplete(long timeout, TimeUnit unit) {
        return true;
    }

    @Deprecated
    public final <A> CompletionState read(boolean block, long timeout,
            TimeUnit unit, A attachment, CompletionCheck check,
            CompletionHandler<Long, ? super A> handler, ByteBuffer... dsts) {
        return read(block ? BlockingMode.BLOCK : BlockingMode.NON_BLOCK,
                timeout, unit, attachment, check, handler, dsts);
    }

    /**
     * Scatter read. The completion handler will be called once some
     * data has been read or an error occurred. If a CompletionCheck
     * object has been provided, the completion handler will only be
     * called if the callHandler method returned true. If no
     * CompletionCheck object has been provided, the default NIO2
     * behavior is used: the completion handler will be called as soon
     * as some data has been read, even if the read has completed inline.
     *
     * @param block is the blocking mode that will be used for this operation
     * @param timeout timeout duration for the read
     * @param unit units for the timeout duration
     * @param attachment an object to attach to the I/O operation that will be
     *        used when calling the completion handler
     * @param check for the IO operation completion
     * @param handler to call when the IO is complete
     * @param dsts buffers
     * @param <A> The attachment type
     * @return the completion state (done, done inline, or still pending)
     */
    public final <A> CompletionState read(BlockingMode block, long timeout,
            TimeUnit unit, A attachment, CompletionCheck check,
            CompletionHandler<Long, ? super A> handler, ByteBuffer... dsts) {
        if (dsts == null) {
            throw new IllegalArgumentException();
        }
        return read(dsts, 0, dsts.length, block, timeout, unit, attachment, check, handler);
    }

    /**
     * Scatter read. The completion handler will be called once some
     * data has been read or an error occurred. If a CompletionCheck
     * object has been provided, the completion handler will only be
     * called if the callHandler method returned true. If no
     * CompletionCheck object has been provided, the default NIO2
     * behavior is used: the completion handler will be called as soon
     * as some data has been read, even if the read has completed inline.
     *
     * @param dsts buffers
     * @param offset in the buffer array
     * @param length in the buffer array
     * @param block is the blocking mode that will be used for this operation
     * @param timeout timeout duration for the read
     * @param unit units for the timeout duration
     * @param attachment an object to attach to the I/O operation that will be
     *        used when calling the completion handler
     * @param check for the IO operation completion
     * @param handler to call when the IO is complete
     * @param <A> The attachment type
     * @return the completion state (done, done inline, or still pending)
     */
    public <A> CompletionState read(ByteBuffer[] dsts, int offset, int length,
            BlockingMode block, long timeout, TimeUnit unit, A attachment,
            CompletionCheck check, CompletionHandler<Long, ? super A> handler) {
        throw new UnsupportedOperationException();
    }

    @Deprecated
    public final <A> CompletionState write(boolean block, long timeout,
            TimeUnit unit, A attachment, CompletionCheck check,
            CompletionHandler<Long, ? super A> handler, ByteBuffer... srcs) {
        return write(block ? BlockingMode.BLOCK : BlockingMode.NON_BLOCK,
                timeout, unit, attachment, check, handler, srcs);
    }

    /**
     * Gather write. The completion handler will be called once some
     * data has been written or an error occurred. If a CompletionCheck
     * object has been provided, the completion handler will only be
     * called if the callHandler method returned true. If no
     * CompletionCheck object has been provided, the default NIO2
     * behavior is used: the completion handler will be called, even
     * if the write is incomplete and data remains in the buffers, or
     * if the write completed inline.
     *
     * @param block is the blocking mode that will be used for this operation
     * @param timeout timeout duration for the write
     * @param unit units for the timeout duration
     * @param attachment an object to attach to the I/O operation that will be
     *        used when calling the completion handler
     * @param check for the IO operation completion
     * @param handler to call when the IO is complete
     * @param srcs buffers
     * @param <A> The attachment type
     * @return the completion state (done, done inline, or still pending)
     */
    public final <A> CompletionState write(BlockingMode block, long timeout,
            TimeUnit unit, A attachment, CompletionCheck check,
            CompletionHandler<Long, ? super A> handler, ByteBuffer... srcs) {
        if (srcs == null) {
            throw new IllegalArgumentException();
        }
        return write(srcs, 0, srcs.length, block, timeout, unit, attachment, check, handler);
    }

    /**
     * Gather write. The completion handler will be called once some
     * data has been written or an error occurred. If a CompletionCheck
     * object has been provided, the completion handler will only be
     * called if the callHandler method returned true. If no
     * CompletionCheck object has been provided, the default NIO2
     * behavior is used: the completion handler will be called, even
     * if the write is incomplete and data remains in the buffers, or
     * if the write completed inline.
     *
     * @param srcs buffers
     * @param offset in the buffer array
     * @param length in the buffer array
     * @param block is the blocking mode that will be used for this operation
     * @param timeout timeout duration for the write
     * @param unit units for the timeout duration
     * @param attachment an object to attach to the I/O operation that will be
     *        used when calling the completion handler
     * @param check for the IO operation completion
     * @param handler to call when the IO is complete
     * @param <A> The attachment type
     * @return the completion state (done, done inline, or still pending)
     */
    public <A> CompletionState write(ByteBuffer[] srcs, int offset, int length,
            BlockingMode block, long timeout, TimeUnit unit, A attachment,
            CompletionCheck check, CompletionHandler<Long, ? super A> handler) {
        throw new UnsupportedOperationException();
    }


    // --------------------------------------------------------- Utility methods

    protected static int transfer(byte[] from, int offset, int length, ByteBuffer to) {
        int max = Math.min(length, to.remaining());
        if (max > 0) {
            to.put(from, offset, max);
        }
        return max;
    }

    protected static int transfer(ByteBuffer from, ByteBuffer to) {
        int max = Math.min(from.remaining(), to.remaining());
        if (max > 0) {
            int fromLimit = from.limit();
            from.limit(from.position() + max);
            to.put(from);
            from.limit(fromLimit);
        }
        return max;
    }
}
