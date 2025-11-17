#!/usr/bin/env python3
"""
Performance Monitor for SDN Controllers
Monitors CPU, Memory, and Latency for Rule-Based vs ML-Based detection
"""

import psutil
import time
import json
import sys
from datetime import datetime
import subprocess
import os

class ControllerPerformanceMonitor:
    def __init__(self, controller_name="ryu-manager"):
        self.controller_name = controller_name
        self.process = None
        self.baseline_metrics = {}
        self.monitoring_data = []
        
    def find_controller_process(self):
        """Find the Ryu controller process"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and any('ryu-manager' in cmd for cmd in cmdline):
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None
    
    def get_baseline_metrics(self):
        """Get baseline system metrics before monitoring"""
        self.baseline_metrics = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_available_mb': psutil.virtual_memory().available / (1024 * 1024)
        }
        print("Baseline System Metrics:")
        print(f"  CPU Usage: {self.baseline_metrics['cpu_percent']:.2f}%")
        print(f"  Memory Usage: {self.baseline_metrics['memory_percent']:.2f}%")
        print(f"  Available Memory: {self.baseline_metrics['memory_available_mb']:.2f} MB")
    
    def monitor_controller(self, duration=60, interval=1):
        """
        Monitor controller performance
        
        Args:
            duration: Monitoring duration in seconds
            interval: Sampling interval in seconds
        """
        self.process = self.find_controller_process()
        
        if not self.process:
            print("❌ Controller process not found!")
            print("Make sure Ryu controller is running:")
            print("  ryu-manager controller.py --verbose")
            return None
        
        print(f"\n✓ Found controller process: PID={self.process.pid}")
        print(f"  Command: {' '.join(self.process.cmdline())}")
        print(f"\nMonitoring for {duration} seconds (sampling every {interval}s)...")
        print("="*70)
        
        start_time = time.time()
        samples = 0
        
        try:
            while time.time() - start_time < duration:
                try:
                    # Get process metrics
                    cpu_percent = self.process.cpu_percent(interval=0.1)
                    memory_info = self.process.memory_info()
                    memory_mb = memory_info.rss / (1024 * 1024)  # RSS in MB
                    memory_percent = self.process.memory_percent()
                    
                    # Get thread count
                    num_threads = self.process.num_threads()
                    
                    # Get I/O stats if available
                    try:
                        io_counters = self.process.io_counters()
                        read_bytes = io_counters.read_bytes / (1024 * 1024)  # MB
                        write_bytes = io_counters.write_bytes / (1024 * 1024)  # MB
                    except:
                        read_bytes = 0
                        write_bytes = 0
                    
                    sample = {
                        'timestamp': datetime.now().isoformat(),
                        'elapsed_time': time.time() - start_time,
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb,
                        'memory_percent': memory_percent,
                        'num_threads': num_threads,
                        'io_read_mb': read_bytes,
                        'io_write_mb': write_bytes
                    }
                    
                    self.monitoring_data.append(sample)
                    samples += 1
                    
                    # Print progress every 10 seconds
                    if samples % 10 == 0:
                        print(f"[{samples}s] CPU: {cpu_percent:.1f}% | "
                              f"Memory: {memory_mb:.1f} MB ({memory_percent:.1f}%) | "
                              f"Threads: {num_threads}")
                    
                    time.sleep(interval)
                    
                except psutil.NoSuchProcess:
                    print("❌ Controller process terminated")
                    break
        
        except KeyboardInterrupt:
            print("\n⚠️  Monitoring interrupted by user")
        
        print("="*70)
        return self.monitoring_data
    
    def calculate_statistics(self):
        """Calculate performance statistics"""
        if not self.monitoring_data:
            return None
        
        import numpy as np
        
        cpu_values = [s['cpu_percent'] for s in self.monitoring_data]
        memory_values = [s['memory_mb'] for s in self.monitoring_data]
        memory_percent_values = [s['memory_percent'] for s in self.monitoring_data]
        thread_values = [s['num_threads'] for s in self.monitoring_data]
        
        stats = {
            'samples': len(self.monitoring_data),
            'duration': self.monitoring_data[-1]['elapsed_time'],
            'cpu': {
                'min': np.min(cpu_values),
                'max': np.max(cpu_values),
                'mean': np.mean(cpu_values),
                'median': np.median(cpu_values),
                'std': np.std(cpu_values),
                'p95': np.percentile(cpu_values, 95),
                'p99': np.percentile(cpu_values, 99)
            },
            'memory_mb': {
                'min': np.min(memory_values),
                'max': np.max(memory_values),
                'mean': np.mean(memory_values),
                'median': np.median(memory_values),
                'std': np.std(memory_values),
                'p95': np.percentile(memory_values, 95),
                'p99': np.percentile(memory_values, 99)
            },
            'memory_percent': {
                'min': np.min(memory_percent_values),
                'max': np.max(memory_percent_values),
                'mean': np.mean(memory_percent_values),
                'median': np.median(memory_percent_values),
            },
            'threads': {
                'min': int(np.min(thread_values)),
                'max': int(np.max(thread_values)),
                'mean': np.mean(thread_values)
            }
        }
        
        return stats
    
    def print_statistics(self, stats, controller_type="Controller"):
        """Print formatted statistics"""
        if not stats:
            print("No statistics available")
            return
        
        print("\n" + "="*70)
        print(f"PERFORMANCE STATISTICS - {controller_type}")
        print("="*70)
        
        print(f"\nMonitoring Info:")
        print(f"  Duration: {stats['duration']:.1f} seconds")
        print(f"  Samples: {stats['samples']}")
        
        print(f"\n📊 CPU Usage:")
        print(f"  Mean:     {stats['cpu']['mean']:.2f}%")
        print(f"  Median:   {stats['cpu']['median']:.2f}%")
        print(f"  Min:      {stats['cpu']['min']:.2f}%")
        print(f"  Max:      {stats['cpu']['max']:.2f}%")
        print(f"  Std Dev:  {stats['cpu']['std']:.2f}%")
        print(f"  95th %ile: {stats['cpu']['p95']:.2f}%")
        print(f"  99th %ile: {stats['cpu']['p99']:.2f}%")
        
        print(f"\n💾 Memory Usage:")
        print(f"  Mean:     {stats['memory_mb']['mean']:.2f} MB "
              f"({stats['memory_percent']['mean']:.2f}%)")
        print(f"  Median:   {stats['memory_mb']['median']:.2f} MB "
              f"({stats['memory_percent']['median']:.2f}%)")
        print(f"  Min:      {stats['memory_mb']['min']:.2f} MB "
              f"({stats['memory_percent']['min']:.2f}%)")
        print(f"  Max:      {stats['memory_mb']['max']:.2f} MB "
              f"({stats['memory_percent']['max']:.2f}%)")
        print(f"  Std Dev:  {stats['memory_mb']['std']:.2f} MB")
        
        print(f"\n🧵 Threads:")
        print(f"  Mean:     {stats['threads']['mean']:.1f}")
        print(f"  Min:      {stats['threads']['min']}")
        print(f"  Max:      {stats['threads']['max']}")
        
        print("="*70)
    
    def save_results(self, stats, filename):
        """Save results to JSON file"""
        results = {
            'controller_type': filename.replace('.json', ''),
            'baseline': self.baseline_metrics,
            'statistics': stats,
            'raw_data': self.monitoring_data
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Results saved to {filename}")
    
    def compare_controllers(self, rule_based_file, ml_based_file):
        """Compare performance between rule-based and ML-based"""
        
        try:
            with open(rule_based_file, 'r') as f:
                rule_data = json.load(f)
            
            with open(ml_based_file, 'r') as f:
                ml_data = json.load(f)
        except FileNotFoundError as e:
            print(f"❌ File not found: {e}")
            return
        
        rb_stats = rule_data['statistics']
        ml_stats = ml_data['statistics']
        
        print("\n" + "="*70)
        print("PERFORMANCE COMPARISON: Rule-Based vs ML-Based")
        print("="*70)
        
        # CPU Comparison
        print("\n📊 CPU Usage Comparison:")
        print(f"{'Metric':<20} {'Rule-Based':<15} {'ML-Based':<15} {'Difference':<15}")
        print("-"*70)
        
        cpu_metrics = ['mean', 'median', 'max', 'p95', 'p99']
        for metric in cpu_metrics:
            rb_val = rb_stats['cpu'][metric]
            ml_val = ml_stats['cpu'][metric]
            diff = ml_val - rb_val
            diff_pct = (diff / rb_val * 100) if rb_val > 0 else 0
            
            print(f"{metric.capitalize():<20} {rb_val:>6.2f}%{'':<8} "
                  f"{ml_val:>6.2f}%{'':<8} "
                  f"{diff:>+6.2f}% ({diff_pct:>+5.1f}%)")
        
        # Memory Comparison
        print("\n💾 Memory Usage Comparison:")
        print(f"{'Metric':<20} {'Rule-Based':<15} {'ML-Based':<15} {'Difference':<15}")
        print("-"*70)
        
        mem_metrics = ['mean', 'median', 'max']
        for metric in mem_metrics:
            rb_val = rb_stats['memory_mb'][metric]
            ml_val = ml_stats['memory_mb'][metric]
            diff = ml_val - rb_val
            diff_pct = (diff / rb_val * 100) if rb_val > 0 else 0
            
            print(f"{metric.capitalize():<20} {rb_val:>6.2f} MB{'':<6} "
                  f"{ml_val:>6.2f} MB{'':<6} "
                  f"{diff:>+6.2f} MB ({diff_pct:>+5.1f}%)")
        
        # Thread Comparison
        print("\n🧵 Thread Comparison:")
        rb_threads = rb_stats['threads']['mean']
        ml_threads = ml_stats['threads']['mean']
        print(f"  Rule-Based: {rb_threads:.1f} threads")
        print(f"  ML-Based:   {ml_threads:.1f} threads")
        print(f"  Difference: {ml_threads - rb_threads:+.1f} threads")
        
        # Summary
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        
        cpu_overhead = ((ml_stats['cpu']['mean'] - rb_stats['cpu']['mean']) / 
                       rb_stats['cpu']['mean'] * 100) if rb_stats['cpu']['mean'] > 0 else 0
        
        mem_overhead = ((ml_stats['memory_mb']['mean'] - rb_stats['memory_mb']['mean']) / 
                       rb_stats['memory_mb']['mean'] * 100) if rb_stats['memory_mb']['mean'] > 0 else 0
        
        print(f"\nML-Based Controller Overhead:")
        print(f"  CPU:    {cpu_overhead:+.1f}% ({ml_stats['cpu']['mean']:.2f}% vs {rb_stats['cpu']['mean']:.2f}%)")
        print(f"  Memory: {mem_overhead:+.1f}% ({ml_stats['memory_mb']['mean']:.2f} MB vs {rb_stats['memory_mb']['mean']:.2f} MB)")
        
        # Interpretation
        print(f"\n💡 Interpretation:")
        if cpu_overhead < 10:
            print(f"  ✅ CPU overhead is LOW ({cpu_overhead:.1f}%) - Acceptable")
        elif cpu_overhead < 25:
            print(f"  ⚠️  CPU overhead is MODERATE ({cpu_overhead:.1f}%) - Manageable")
        else:
            print(f"  ❌ CPU overhead is HIGH ({cpu_overhead:.1f}%) - Consider optimization")
        
        if mem_overhead < 20:
            print(f"  ✅ Memory overhead is LOW ({mem_overhead:.1f}%) - Acceptable")
        elif mem_overhead < 50:
            print(f"  ⚠️  Memory overhead is MODERATE ({mem_overhead:.1f}%) - Manageable")
        else:
            print(f"  ❌ Memory overhead is HIGH ({mem_overhead:.1f}%) - Consider optimization")
        
        print("="*70)


def main():
    """Main monitoring function"""
    
    print("="*70)
    print("SDN Controller Performance Monitor")
    print("="*70)
    
    print("\nWhat would you like to do?")
    print("1. Monitor Rule-Based Controller (controller_3.py)")
    print("2. Monitor ML-Based Controller (production_ml_controller.py)")
    print("3. Compare existing results")
    print("4. Run complete comparison (monitor both)")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    monitor = ControllerPerformanceMonitor()
    
    if choice == '1':
        print("\n📊 Monitoring Rule-Based Controller...")
        print("Make sure it's running: ryu-manager controller_3.py --verbose")
        input("Press Enter when ready...")
        
        monitor.get_baseline_metrics()
        duration = int(input("\nMonitoring duration (seconds, default 60): ") or "60")
        
        data = monitor.monitor_controller(duration=duration)
        if data:
            stats = monitor.calculate_statistics()
            monitor.print_statistics(stats, "Rule-Based Controller")
            monitor.save_results(stats, "rule_based_performance.json")
    
    elif choice == '2':
        print("\n📊 Monitoring ML-Based Controller...")
        print("Make sure it's running: ryu-manager production_ml_controller.py --verbose")
        input("Press Enter when ready...")
        
        monitor.get_baseline_metrics()
        duration = int(input("\nMonitoring duration (seconds, default 60): ") or "60")
        
        data = monitor.monitor_controller(duration=duration)
        if data:
            stats = monitor.calculate_statistics()
            monitor.print_statistics(stats, "ML-Based Controller")
            monitor.save_results(stats, "ml_based_performance.json")
    
    elif choice == '3':
        print("\n📊 Comparing Controllers...")
        monitor.compare_controllers('rule_based_performance.json', 
                                    'ml_based_performance.json')
    
    elif choice == '4':
        print("\n📊 Running Complete Comparison...")
        print("\nThis will monitor both controllers sequentially.")
        print("You'll need to:")
        print("  1. Start rule-based controller")
        print("  2. Generate traffic")
        print("  3. Stop and switch to ML-based")
        print("  4. Generate same traffic again")
        
        input("\nPress Enter to continue...")
        
        # Monitor rule-based
        print("\n" + "="*70)
        print("STEP 1: Monitor Rule-Based Controller")
        print("="*70)
        print("\nStart rule-based controller now:")
        print("  ryu-manager controller_3.py --verbose")
        input("Press Enter when ready...")
        
        monitor1 = ControllerPerformanceMonitor()
        monitor1.get_baseline_metrics()
        data1 = monitor1.monitor_controller(duration=60)
        
        if data1:
            stats1 = monitor1.calculate_statistics()
            monitor1.print_statistics(stats1, "Rule-Based Controller")
            monitor1.save_results(stats1, "rule_based_performance.json")
        
        print("\n⚠️  Stop rule-based controller (Ctrl+C)")
        input("Press Enter when stopped...")
        
        # Monitor ML-based
        print("\n" + "="*70)
        print("STEP 2: Monitor ML-Based Controller")
        print("="*70)
        print("\nStart ML-based controller now:")
        print("  ryu-manager production_ml_controller.py --verbose")
        input("Press Enter when ready...")
        
        monitor2 = ControllerPerformanceMonitor()
        monitor2.get_baseline_metrics()
        data2 = monitor2.monitor_controller(duration=60)
        
        if data2:
            stats2 = monitor2.calculate_statistics()
            monitor2.print_statistics(stats2, "ML-Based Controller")
            monitor2.save_results(stats2, "ml_based_performance.json")
        
        # Compare
        if data1 and data2:
            monitor.compare_controllers('rule_based_performance.json',
                                       'ml_based_performance.json')
    
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()
