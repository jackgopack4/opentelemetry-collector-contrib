// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ottlfuncs // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

type DeleteMatchingKeysArguments[K any] struct {
	Target  ottl.PMapGetSetter[K]
	Pattern string
}

func NewDeleteMatchingKeysFactory[K any]() ottl.Factory[K] {
	return ottl.NewFactory("delete_matching_keys", &DeleteMatchingKeysArguments[K]{}, createDeleteMatchingKeysFunction[K])
}

func createDeleteMatchingKeysFunction[K any](_ ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[K], error) {
	args, ok := oArgs.(*DeleteMatchingKeysArguments[K])

	if !ok {
		return nil, errors.New("DeleteMatchingKeysFactory args must be of type *DeleteMatchingKeysArguments[K]")
	}

	return deleteMatchingKeys(args.Target, args.Pattern)
}

func deleteMatchingKeys[K any](target ottl.PMapGetSetter[K], pattern string) (ottl.ExprFunc[K], error) {
	compiledPattern, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("the regex pattern supplied to delete_matching_keys is not a valid pattern: %w", err)
	}
	return func(ctx context.Context, tCtx K) (any, error) {
		val, err := target.Get(ctx, tCtx)
		if err != nil {
			return nil, err
		}
		val.RemoveIf(func(key string, _ pcommon.Value) bool {
			return compiledPattern.MatchString(key)
		})
		return nil, target.Set(ctx, tCtx, val)
	}, nil
}
