package utils

import (
	"crypto/sha256"
	"encoding/binary"
	commommodel "gateway/src/models/common"
	"math/rand"
)

// PickRoundRobin 返回一个基于轮询的选择结果。
func PickRoundRobin(instances []*commommodel.ServiceInstance, counter int) *commommodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	return instances[counter%len(instances)]
}

// PickLeastWeightedLatency 返回一个基于最少加权延迟的选择结果。
func PickLeastWeightedLatency(
	instances []*commommodel.ServiceInstance,
	latency map[string]float64,
) *commommodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	var best *commommodel.ServiceInstance
	var bestScore float64 = -1
	for _, inst := range instances {
		l, ok := latency[inst.ID.String()]
		if !ok {
			l = 0
		}
		score := l / float64(inst.Weight)
		if best == nil || score < bestScore {
			best = inst
			bestScore = score
		}
	}
	return best
}

// PickHashAffinity 返回一个基于哈希亲和性的选择结果。
func PickHashAffinity(instances []*commommodel.ServiceInstance, affinityKey string) *commommodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	sum := sha256.Sum256([]byte(affinityKey))
	hash := binary.BigEndian.Uint64(sum[:8])
	index := int(hash % uint64(len(instances)))
	return instances[index]
}

// FilterByTags 根据 requireTags 过滤实例列表，返回包含所有 requireTags 的实例。
func FilterByTags(instances []*commommodel.ServiceInstance, requireTags []string) []*commommodel.ServiceInstance {
	if len(requireTags) == 0 {
		return instances
	}
	containsAllTags := func(instTags, reqTags []string) bool {
		tagSet := make(map[string]struct{}, len(instTags))
		for _, t := range instTags {
			tagSet[t] = struct{}{}
		}
		for _, rt := range reqTags {
			if _, ok := tagSet[rt]; !ok {
				return false
			}
		}
		return true
	}
	var result []*commommodel.ServiceInstance
	for _, inst := range instances {
		if containsAllTags(inst.Tags, requireTags) {
			result = append(result, inst)
		}
	}
	return result
}

// RandomWeighted 返回一个基于权重随机选择的实例。
func RandomWeighted(instances []*commommodel.ServiceInstance) *commommodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	totalWeight := 0
	for _, inst := range instances {
		totalWeight += inst.Weight
	}
	if totalWeight <= 0 {
		return instances[0]
	}
	r := rand.Intn(totalWeight)
	for _, inst := range instances {
		r -= inst.Weight
		if r < 0 {
			return inst
		}
	}
	return instances[len(instances)-1]
}
