import sys

def getcfg(sess):
    try:
        rv = sess.get_items('/turing-machine:turing-machine/transition-function//*')
        print 'got', repr(rv)
        print 'len', len(rv)
        for i in range(0, len(rv)):
            print 'item', i, 'val', repr(rv[i])
    except:
        sys.excepthook(*sys.exc_info())

def myfunc(sess, *args, **kwargs):
    print 'myfunc', repr(args), repr(kwargs)
    getcfg(sess)

def init(sess):
    print 'init', repr(sess)
    sess.subscribe('turing-machine', myfunc, None)
    getcfg(sess)

