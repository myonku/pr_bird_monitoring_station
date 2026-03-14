package utils

import (
	registrymodel "gateway/src/models/registry"
	"math/rand"
)

// PickRoundRobin 返回一个基于轮询的选择结果。
func PickRoundRobin(instances []*registrymodel.ServiceInstance, counter int) *registrymodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	return instances[counter%len(instances)]
}

// PickLeastWeightedLatency 返回一个基于最少加权延迟的选择结果。
func PickLeastWeightedLatency(
	instances []*registrymodel.ServiceInstance,
	latency map[string]float64,
) *registrymodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	var best *registrymodel.ServiceInstance
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
func PickHashAffinity(instances []*registrymodel.ServiceInstance, affinityKey string) *registrymodel.ServiceInstance {
	if len(instances) == 0 {
		return nil
	}
	hash := 0
	for i := 0; i < len(affinityKey); i++ {
		hash = int(affinityKey[i]) + (hash << 6) + (hash << 16) - hash
	}
	index := hash % len(instances)
	return instances[index]
}

// FilterByTags 根据 requireTags 过滤实例列表，返回包含所有 requireTags 的实例。
func FilterByTags(instances []*registrymodel.ServiceInstance, requireTags []string) []*registrymodel.ServiceInstance {
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
	var result []*registrymodel.ServiceInstance
	for _, inst := range instances {
		if containsAllTags(inst.Tags, requireTags) {
			result = append(result, inst)
		}
	}
	return result
}

// RandomWeighted 返回一个基于权重随机选择的实例。
func RandomWeighted(instances []*registrymodel.ServiceInstance) *registrymodel.ServiceInstance {
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
