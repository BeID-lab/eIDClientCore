/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__TRANSCEIVER_INCLUDED__)
#define __TRANSCEIVER_INCLUDED__

#include <queue>
#include <vector>

template <class S, class R> class Transceiver
{
    public:
        virtual R transceive(const S& cmd) = 0;
        virtual std::vector<R> transceive(const std::vector<S> &cmds)
        {
            std::vector<R> resps;
            for (size_t i = 0; i < cmds.size(); i++)
                resps.push_back(this->transceive(cmds[i]));
            return resps;
        };

        virtual void send(const S& cmd) = 0;
        virtual void send(const std::vector<S> &cmds)
        {
            for (size_t i = 0; i < cmds.size(); i++)
                send(cmds[i]);
        };

		virtual R receive(void) = 0;
        virtual std::vector<R> receive(size_t count)
        {
            std::vector<R> resps;
            while (count > 0) {
                resps.push_back(receive());
                count--;
            }
            return resps;
        };
};

/** FIXME currently all APDUs sent via send() must be fetched with receive()
 * before transceive() can be used as expected.
 * TODO add message identifiers to allow concurrent calls to send()/receive()
 * and transceive() */
template <class S, class R> class SynchronousTransceiver: public Transceiver<S, R>
{
	protected:
        std::queue<R> resps;

	public:
		virtual void send(const S& cmd)
		{
			resps.push(this->transceive(cmd));
		};
        virtual void send(const std::vector<S> &cmds)
        {
            this->send(cmds);
        };

		virtual R receive(void)
		{
            R r = resps.front();
			resps.pop();
            return r;
		};
        virtual std::vector<R> receive(size_t count)
        {
            return this->receive(count);
        };
};

template <class S, class R> class AsynchronousTransceiver: public Transceiver<S, R>
{
	public:
		virtual R transceive(const S& cmd)
		{
			this->send(cmd);
			return this->receive();
		};
		virtual std::vector<R> transceive(const std::vector<S>& cmds)
		{
			this->send(cmds);
			return this->receive(cmds.size());
		};
};

#endif
