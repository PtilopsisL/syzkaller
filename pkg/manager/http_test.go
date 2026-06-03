// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

func TestHttpTemplates(t *testing.T) {
	for i, typ := range templTypes {
		t.Run(fmt.Sprintf("%v_%T", i, typ.data), func(t *testing.T) {
			data := testutil.RandValue(t, typ.data)
			if err := typ.templ.Execute(io.Discard, data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPVMsWithoutPoolListsAllPools(t *testing.T) {
	serv := &HTTPServer{
		Cfg: &mgrconfig.Config{Name: "test-manager"},
		Pools: map[string]*vm.Dispatcher{
			"primary": dispatcher.NewPool[*vm.Instance](1, nil, nil),
			"v6.1":    dispatcher.NewPool[*vm.Instance](1, nil, nil),
		},
	}

	w := httptest.NewRecorder()
	serv.httpVMs(w, httptest.NewRequest(http.MethodGet, "/vms", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"primary/#0", "v6.1/#0"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response does not contain %q:\n%s", want, body)
		}
	}
}

func TestVMInfoLinkIncludesPool(t *testing.T) {
	link := vmInfoLink("machine-info", "v6.1", 3)
	for _, want := range []string{"/vm?", "id=3", "pool=v6.1", "type=machine-info"} {
		if !strings.Contains(link, want) {
			t.Fatalf("link %q does not contain %q", link, want)
		}
	}
}
