package layers

import (
	"regexp"

	"github.com/9seconds/httransform/v2/dialers"
	"github.com/9seconds/httransform/v2/errors"
	"github.com/9seconds/httransform/v2/executor"
	"github.com/9seconds/httransform/v2/layers"
	log "github.com/sirupsen/logrus"
)

var errDirectAccess = errors.Annotate(nil, "direct access to the URL", "direct_executor", 0)

type DirectAccessLayer struct {
	rules    []*regexp.Regexp
	notRules []*regexp.Regexp
	executor executor.Executor
}

func (d *DirectAccessLayer) OnRequest(ctx *layers.Context) error {
	url := ctx.Request().URI()
	hostpath := make([]byte, 0, len(url.Host())+len(url.RequestURI()))
	hostpath = append(hostpath, url.Host()...)
	hostpath = append(hostpath, url.RequestURI()...)

	logger := getLogger(ctx)
	logger.WithFields(log.Fields{"hostpath": string(hostpath)}).Debug("OnRequest")

	for _, v := range d.notRules {
		if v.Match(hostpath) {
			logger.WithFields(log.Fields{"hostpath": string(hostpath), "match": v.String()}).Debug("Match not rule")
			return nil
		}
	}

	for _, v := range d.rules {
		if v.Match(hostpath) {
			logger.WithFields(log.Fields{"hostpath": string(hostpath), "match": v.String()}).Debug("Match rule")
			return errDirectAccess
		}
	}

	return nil
}

func (d *DirectAccessLayer) OnResponse(ctx *layers.Context, err error) error {
	if err == errDirectAccess {
		if err := ctx.RequestHeaders.Push(); err != nil {
			return errors.Annotate(err, "cannot sync request headers", "direct_executor", 0)
		}

		if err := d.executor(ctx); err != nil {
			return errors.Annotate(err, "cannot execute a direct request", "direct_executor", 0)
		}

		if err := ctx.ResponseHeaders.Pull(); err != nil {
			return errors.Annotate(err, "cannot read response headers", "direct_executor", 0)
		}

		logger := getLogger(ctx)
		logger.WithFields(log.Fields{}).Debug("Request was direct accessed")

		return nil
	}

	return err
}

func NewDirectAccessLayer(regexps []string, notregexps []string) layers.Layer {
	rules := make([]*regexp.Regexp, len(regexps))
	for i, v := range regexps {
		rules[i] = regexp.MustCompile(v)
	}

	notRules := make([]*regexp.Regexp, len(notregexps))
	for i, v := range notregexps {
		notRules[i] = regexp.MustCompile(v)
	}

	return &DirectAccessLayer{
		rules:    rules,
		notRules: notRules,
		executor: executor.MakeDefaultExecutor(dialers.NewBase(dialers.Opts{})),
	}
}
