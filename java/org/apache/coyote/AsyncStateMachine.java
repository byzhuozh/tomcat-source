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
package org.apache.coyote;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.res.StringManager;
import org.apache.tomcat.util.security.PrivilegedGetTccl;
import org.apache.tomcat.util.security.PrivilegedSetTccl;

/**
 * Manages the state transitions for async requests.
 *
 * <pre>
 * The internal states that are used are:
 * DISPATCHED       - Standard request. Not in Async mode.
 * STARTING         - ServletRequest.startAsync() has been called but the
 *                    request in which that call was made has not finished
 *                    processing.
 * STARTED          - ServletRequest.startAsync() has been called and the
 *                    request in which that call was made has finished
 *                    processing.
 * READ_WRITE_OP    - Performing an asynchronous read or write.
 * MUST_COMPLETE    - ServletRequest.startAsync() followed by complete() have
 *                    been called during a single Servlet.service() method. The
 *                    complete() will be processed as soon as the request
 *                    finishes.
 * COMPLETE_PENDING - ServletRequest.startAsync() has been called and before the
 *                    request in which that call was had finished processing,
 *                    complete() was called for a non-container thread. The
 *                    complete() will be processed as soon as the request
 *                    finishes. This is different to MUST_COMPLETE because of
 *                    differences required to avoid race conditions during error
 *                    handling.
 * COMPLETING       - The call to complete() was made once the request was in
 *                    the STARTED state. May or may not be triggered by a
 *                    container thread - depends if start(Runnable) was used.
 * TIMING_OUT       - The async request has timed out and is waiting for a call
 *                    to complete(). If that isn't made, the error state will
 *                    entered.
 * MUST_DISPATCH    - ServletRequest.startAsync() followed by dispatch() have
 *                    been called during a single Servlet.service() method. The
 *                    dispatch() will be processed as soon as the request
 *                    finishes.
 * DISPATCH_PENDING - ServletRequest.startAsync() has been called and before the
 *                    request in which that call was had finished processing,
 *                    dispatch() was called for a non-container thread. The
 *                    dispatch() will be processed as soon as the request
 *                    finishes. This is different to MUST_DISPATCH because of
 *                    differences required to avoid race conditions during error
 *                    handling.
 * DISPATCHING      - The dispatch is being processed.
 * MUST_ERROR       - ServletRequest.startAsync() has been called followed by an
 *                    I/O error on a non-container thread. The main purpose of
 *                    this state is to prevent additional async actions
 *                    (complete(), dispatch() etc.) on the non-container thread.
 *                    The container will perform the necessary error handling,
 *                    including ensuring that the AsyncLister.onError() method
 *                    is called.
 * ERROR            - Something went wrong.
 *
 *                           |-----«-------------------------------«------------------------------|
 *                           |                                                                    |
 *                           |      error()                                                       |
 * |-----------------»---|   |  |--«--------MUST_ERROR---------------«------------------------|   |
 * |                    \|/ \|/\|/                                                            |   |
 * |   |----------«-----E R R O R--«-----------------------«-------------------------------|  |   |
 * |   |      complete() /|\/|\\ \-«--------------------------------«-------|              |  |   |
 * |   |                  |  |  \                                           |              |  |   |
 * |   |    |-----»-------|  |   \-----------»----------|                   |              |  |   |
 * |   |    |                |                          |dispatch()         |              |  ^   |
 * |   |    |                |                         \|/                  ^              |  |   |
 * |   |    |                |          |--|timeout()   |                   |              |  |   |
 * |   |    |     post()     |          | \|/           |     post()        |              |  |   |
 * |   |    |    |---------- | --»DISPATCHED«---------- | --------------COMPLETING«-----|  |  |   |
 * |   |    |    |           |   /|\/|\ |               |                | /|\ /|\      |  |  |   |
 * |   |    |    |    |---»- | ---|  |  |startAsync()   |       timeout()|--|   |       |  |  |   |
 * |   |    ^    ^    |      |       |  |               |                       |       |  ^  |   |
 * |   |    |    |    |   |-- \ -----|  |   complete()  |                       |post() |  |  |   |
 * |   |    |    |    |   |    \        |     /--»----- | ---COMPLETE_PENDING-»-|       ^  |  |   |
 * |   |    |    |    |   |     \       |    /          |                               |  |  |   |
 * |   |    |    |    |   ^      \      |   /           |                    complete() |  |  |   |
 * |  \|/   |    |    |   |       \    \|/ /   post()   |                     /---»-----|  |  ^   |
 * | MUST_COMPLETE-«- | - | --«----STARTING--»--------- | ------------|      /             |  |   |
 * |  /|\    /|\      |   |  complete()  | \            |             |     /   error()    |  |   ^
 * |   |      |       |   |              |  \           |             |    //---»----------|  |   |
 * |   |      |       ^   |    dispatch()|   \          |    post()   |   //                  |   |
 * |   |      |       |   |              |    \         |    |-----|  |  //   nct-io-error    |   |
 * |   |      |       |   |              |     \        |    |     |  | ///---»---------------|   |
 * |   |      |       |   |             \|/     \       |    |    \|/\| |||                       |
 * |   |      |       |   |--«--MUST_DISPATCH-----«-----|    |--«--STARTED«---------«---------|   |
 * |   |      |       | dispatched() /|\   |      \               / |   |        post()       |   |
 * |   |      |       |               |    |       \             /  |   |                     |   |
 * |   |      |       |               |    |        \           /   |   |                     |   |
 * |   |      |       |               |    |post()  |           |   |   |                     ^   |
 * ^   |      ^       |               |    |       \|/          |   |   |asyncOperation()     |   |
 * |   |      |       ^               |    |  DISPATCH_PENDING  |   |   |                     |   |
 * |   |      |       |               |    |  |post()           |   |   |                     |   |
 * |   |      |       |               |    |  |      |----------|   |   |»-READ_WRITE_OP--»---|   |
 * |   |      |       |               |    |  |      |  dispatch()  |            |  |  |          |
 * |   |      |       |               |    |  |      |              |            |  |  |          |
 * |   |      |       |post()         |    |  |      |     timeout()|            |  |  |   error()|
 * |   |      |       |dispatched()   |   \|/\|/    \|/             |  dispatch()|  |  |-»--------|
 * |   |      |       |---«---------- | ---DISPATCHING«-----«------ | ------«----|  |
 * |   |      |                       |     |    ^                  |               |
 * |   |      |                       |     |----|                  |               |
 * |   |      |                       |    timeout()                |               |
 * |   |      |                       |                             |               |
 * |   |      |                       |       dispatch()           \|/              |
 * |   |      |                       |-----------«-----------TIMING_OUT            |
 * |   |      |                                                 |   |               |
 * |   |      |-------«----------------------------------«------|   |               |
 * |   |                          complete()                        |               |
 * |   |                                                            |               |
 * |«- | ----«-------------------«-------------------------------«--|               |
 *     |                           error()                                          |
 *     |                                                  complete()                |
 *     |----------------------------------------------------------------------------|
 * </pre>
 */
public class AsyncStateMachine {

    /**
     * The string manager for this package.
     */
    private static final StringManager sm = StringManager.getManager(AsyncStateMachine.class);

    private enum AsyncState {
        DISPATCHED(false, false, false, false),
        STARTING(true, true, false, false),
        STARTED(true, true, false, false),
        MUST_COMPLETE(true, true, true, false),
        COMPLETE_PENDING(true, true, false, false),
        COMPLETING(true, false, true, false),
        TIMING_OUT(true, true, false, false),
        MUST_DISPATCH(true, true, false, true),
        DISPATCH_PENDING(true, true, false, false),
        DISPATCHING(true, false, false, true),
        READ_WRITE_OP(true, true, false, false),
        MUST_ERROR(true, true, false, false),
        ERROR(true, true, false, false);

        private final boolean isAsync;
        private final boolean isStarted;
        private final boolean isCompleting;
        private final boolean isDispatching;

        private AsyncState(boolean isAsync, boolean isStarted, boolean isCompleting,
                           boolean isDispatching) {
            this.isAsync = isAsync;
            this.isStarted = isStarted;
            this.isCompleting = isCompleting;
            this.isDispatching = isDispatching;
        }

        public boolean isAsync() {
            return isAsync;
        }

        public boolean isStarted() {
            return isStarted;
        }

        public boolean isDispatching() {
            return isDispatching;
        }

        public boolean isCompleting() {
            return isCompleting;
        }
    }


    private volatile AsyncState state = AsyncState.DISPATCHED;
    private volatile long lastAsyncStart = 0;
    /*
     * Tracks the current generation of async processing for this state machine.
     * The generation is incremented every time async processing is started. The
     * primary purpose of this is to enable Tomcat to detect and prevent
     * attempts to process an event for a previous generation with the current
     * generation as processing such an event usually ends badly:
     * e.g. CVE-2018-8037.
     */
    private final AtomicLong generation = new AtomicLong(0);
    // Need this to fire listener on complete
    private AsyncContextCallback asyncCtxt = null;
    private final AbstractProcessor processor;


    public AsyncStateMachine(AbstractProcessor processor) {
        this.processor = processor;
    }


    public boolean isAsync() {
        return state.isAsync();
    }

    public boolean isAsyncDispatching() {
        return state.isDispatching();
    }

    public boolean isAsyncStarted() {
        return state.isStarted();
    }

    public boolean isAsyncTimingOut() {
        return state == AsyncState.TIMING_OUT;
    }

    public boolean isAsyncError() {
        return state == AsyncState.ERROR;
    }

    public boolean isCompleting() {
        return state.isCompleting();
    }

    /**
     * Obtain the time that this connection last transitioned to async processing.
     *
     * @return The time (as returned by {@link System#currentTimeMillis()}) that this connection last transitioned to
     * async
     */
    public long getLastAsyncStart() {
        return lastAsyncStart;
    }

    long getCurrentGeneration() {
        return generation.get();
    }

    public synchronized void asyncStart(AsyncContextCallback asyncCtxt) {
        if (state == AsyncState.DISPATCHED) {
            generation.incrementAndGet();
            state = AsyncState.STARTING;
            this.asyncCtxt = asyncCtxt;
            lastAsyncStart = System.currentTimeMillis();
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncStart()", state));
        }
    }

    public synchronized void asyncOperation() {
        if (state == AsyncState.STARTED) {
            state = AsyncState.READ_WRITE_OP;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncOperation()", state));
        }
    }

    /*
     * Async has been processed. Whether or not to enter a long poll depends on
     * current state. For example, as per SRV.2.3.3.3 can now process calls to
     * complete() or dispatch().
     */
    public synchronized SocketState asyncPostProcess() {
        if (state == AsyncState.COMPLETE_PENDING) {
            doComplete();
            return SocketState.ASYNC_END;
        } else if (state == AsyncState.DISPATCH_PENDING) {
            doDispatch();
            return SocketState.ASYNC_END;
        } else if (state == AsyncState.STARTING || state == AsyncState.READ_WRITE_OP) {
            state = AsyncState.STARTED;
            return SocketState.LONG;
        } else if (state == AsyncState.MUST_COMPLETE || state == AsyncState.COMPLETING) {
            asyncCtxt.fireOnComplete();
            //异步场景：此时状态机状态状态调整 调度结束
            state = AsyncState.DISPATCHED;
            return SocketState.ASYNC_END;
        } else if (state == AsyncState.MUST_DISPATCH) {
            state = AsyncState.DISPATCHING;
            return SocketState.ASYNC_END;
        } else if (state == AsyncState.DISPATCHING) {
            state = AsyncState.DISPATCHED;
            return SocketState.ASYNC_END;
        } else if (state == AsyncState.STARTED) {
            // This can occur if an async listener does a dispatch to an async
            // servlet during onTimeout
            return SocketState.LONG;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncPostProcess()", state));
        }
    }


    public synchronized boolean asyncComplete() {
        if (!ContainerThreadMarker.isContainerThread() && state == AsyncState.STARTING) {
            state = AsyncState.COMPLETE_PENDING;
            return false;
        } else {
            return doComplete();
        }
    }


    private synchronized boolean doComplete() {
        clearNonBlockingListeners();
        boolean doComplete = false;
        if (state == AsyncState.STARTING || state == AsyncState.TIMING_OUT ||
                state == AsyncState.ERROR || state == AsyncState.READ_WRITE_OP) {
            state = AsyncState.MUST_COMPLETE;
        } else if (state == AsyncState.STARTED || state == AsyncState.COMPLETE_PENDING) {
            state = AsyncState.COMPLETING;
            doComplete = true;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState", "asyncComplete()", state));
        }
        return doComplete;
    }


    public synchronized boolean asyncTimeout() {
        if (state == AsyncState.STARTED) {
            state = AsyncState.TIMING_OUT;
            return true;
        } else if (state == AsyncState.COMPLETING ||
                state == AsyncState.DISPATCHING ||
                state == AsyncState.DISPATCHED) {
            // NOOP - App called complete() or dispatch() between the the
            // timeout firing and execution reaching this point
            return false;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncTimeout()", state));
        }
    }


    public synchronized boolean asyncDispatch() {
        if (!ContainerThreadMarker.isContainerThread() && state == AsyncState.STARTING) {
            state = AsyncState.DISPATCH_PENDING;
            return false;
        } else {
            return doDispatch();
        }
    }


    private synchronized boolean doDispatch() {
        clearNonBlockingListeners();
        boolean doDispatch = false;
        if (state == AsyncState.STARTING ||
                state == AsyncState.TIMING_OUT ||
                state == AsyncState.ERROR) {
            // In these three cases processing is on a container thread so no
            // need to transfer processing to a new container thread
            state = AsyncState.MUST_DISPATCH;
        } else if (state == AsyncState.STARTED || state == AsyncState.DISPATCH_PENDING) {
            state = AsyncState.DISPATCHING;
            // A dispatch is always required.
            // If on a non-container thread, need to get back onto a container
            // thread to complete the processing.
            // If on a container thread the current request/response are not the
            // request/response associated with the AsyncContext so need a new
            // container thread to process the different request/response.
            doDispatch = true;
        } else if (state == AsyncState.READ_WRITE_OP) {
            state = AsyncState.DISPATCHING;
            // If on a container thread then the socket will be added to the
            // poller poller when the thread exits the
            // AbstractConnectionHandler.process() method so don't do a dispatch
            // here which would add it to the poller a second time.
            if (!ContainerThreadMarker.isContainerThread()) {
                doDispatch = true;
            }
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncDispatch()", state));
        }
        return doDispatch;
    }


    public synchronized void asyncDispatched() {
        if (state == AsyncState.DISPATCHING ||
                state == AsyncState.MUST_DISPATCH) {
            state = AsyncState.DISPATCHED;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncDispatched()", state));
        }
    }


    public synchronized void asyncMustError() {
        if (state == AsyncState.STARTED) {
            clearNonBlockingListeners();
            state = AsyncState.MUST_ERROR;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncMustError()", state));
        }
    }


    public synchronized void asyncError() {
        if (state == AsyncState.STARTING ||
                state == AsyncState.STARTED ||
                state == AsyncState.DISPATCHED ||
                state == AsyncState.TIMING_OUT ||
                state == AsyncState.MUST_COMPLETE ||
                state == AsyncState.READ_WRITE_OP ||
                state == AsyncState.COMPLETING ||
                state == AsyncState.MUST_ERROR) {
            clearNonBlockingListeners();
            state = AsyncState.ERROR;
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncError()", state));
        }
    }

    public synchronized void asyncRun(Runnable runnable) {
        if (state == AsyncState.STARTING || state == AsyncState.STARTED ||
                state == AsyncState.READ_WRITE_OP) {
            // Execute the runnable using a container thread from the
            // Connector's thread pool. Use a wrapper to prevent a memory leak
            ClassLoader oldCL;
            if (Constants.IS_SECURITY_ENABLED) {
                PrivilegedAction<ClassLoader> pa = new PrivilegedGetTccl();
                oldCL = AccessController.doPrivileged(pa);
            } else {
                oldCL = Thread.currentThread().getContextClassLoader();
            }
            try {
                if (Constants.IS_SECURITY_ENABLED) {
                    PrivilegedAction<Void> pa = new PrivilegedSetTccl(
                            this.getClass().getClassLoader());
                    AccessController.doPrivileged(pa);
                } else {
                    Thread.currentThread().setContextClassLoader(
                            this.getClass().getClassLoader());
                }

                processor.getExecutor().execute(runnable);
            } finally {
                if (Constants.IS_SECURITY_ENABLED) {
                    PrivilegedAction<Void> pa = new PrivilegedSetTccl(
                            oldCL);
                    AccessController.doPrivileged(pa);
                } else {
                    Thread.currentThread().setContextClassLoader(oldCL);
                }
            }
        } else {
            throw new IllegalStateException(
                    sm.getString("asyncStateMachine.invalidAsyncState",
                            "asyncRun()", state));
        }

    }


    synchronized boolean isAvailable() {
        if (asyncCtxt == null) {
            // Async processing has probably been completed in another thread.
            // Trigger a timeout to make sure the Processor is cleaned up.
            return false;
        }
        return asyncCtxt.isAvailable();
    }


    public synchronized void recycle() {
        // Use lastAsyncStart to determine if this instance has been used since
        // it was last recycled. If it hasn't there is no need to recycle again
        // which saves the relatively expensive call to notifyAll()
        if (lastAsyncStart == 0) {
            return;
        }
        // Ensure in case of error that any non-container threads that have been
        // paused are unpaused.
        notifyAll();
        asyncCtxt = null;
        state = AsyncState.DISPATCHED;
        lastAsyncStart = 0;
    }


    private void clearNonBlockingListeners() {
        processor.getRequest().listener = null;
        processor.getRequest().getResponse().listener = null;
    }
}
