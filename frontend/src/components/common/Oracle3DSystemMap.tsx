"use client";

import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { audioFx } from '../../lib/audio';

interface NodeData {
  id: string;
  name: string;
  pos: [number, number, number];
  color: string;
}

const NODES: NodeData[] = [
  { id: 'CLOUD', name: 'AWS & K8S', pos: [0, 2.2, 0.2], color: '#3b82f6' },
  { id: 'SECURITY', name: 'ZERO-TRUST WIZ', pos: [-2.6, 0.3, 0.3], color: '#ef4444' },
  { id: 'CICD', name: 'ARGO & ACTIONS', pos: [2.6, 0.4, 0.2], color: '#10b981' },
  { id: 'GIT', name: 'GITHUB & JIRA', pos: [-1.8, -1.9, 0.4], color: '#8b5cf6' },
  { id: 'TEAMS', name: 'SLACK COMMAND', pos: [1.8, -1.8, 0.3], color: '#f59e0b' },
];

export const Oracle3DSystemMap: React.FC = () => {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!mountRef.current) return;
    const container = mountRef.current;
    const width = container.clientWidth || 600;
    const height = 280;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 6.5);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);

    // Lights
    const ambient = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambient);
    const pointLight = new THREE.PointLight(0x00f6ff, 2.5, 10);
    pointLight.position.set(0, 0, 3);
    scene.add(pointLight);

    // Core Icosahedron Wireframe
    const coreGeo = new THREE.IcosahedronGeometry(0.8, 1);
    const coreMat = new THREE.MeshStandardMaterial({
      wireframe: true,
      color: 0x00f6ff,
      emissive: 0x00f6ff,
      emissiveIntensity: 1.5,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    group.add(coreMesh);

    // Inner Crystal
    const innerGeo = new THREE.OctahedronGeometry(0.4, 0);
    const innerMat = new THREE.MeshStandardMaterial({
      color: 0x020a14,
      emissive: 0x0080ff,
      emissiveIntensity: 0.8,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    group.add(innerMesh);

    // Gyro Rings
    const ring1 = new THREE.Mesh(
      new THREE.TorusGeometry(1.2, 0.015, 8, 48),
      new THREE.MeshBasicMaterial({ color: 0x00f6ff, transparent: true, opacity: 0.6 })
    );
    const ring2 = new THREE.Mesh(
      new THREE.TorusGeometry(1.5, 0.012, 8, 48),
      new THREE.MeshBasicMaterial({ color: 0x3b82f6, transparent: true, opacity: 0.4 })
    );
    group.add(ring1);
    group.add(ring2);

    // Connection curves
    const curves = NODES.map((n) => {
      const start = new THREE.Vector3(...n.pos);
      const end = new THREE.Vector3(0, 0, 0);
      const mid = new THREE.Vector3((start.x + end.x) * 0.5, (start.y + end.y) * 0.5 + 0.2, (start.z + end.z) * 0.5 + 0.3);
      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(24);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({ color: n.color, transparent: true, opacity: 0.45 });
      const line = new THREE.Line(lineGeo, lineMat);
      group.add(line);
      return curve;
    });

    // Outer satellite nodes
    NODES.forEach((n) => {
      const nodeMesh = new THREE.Mesh(
        new THREE.SphereGeometry(0.18, 16, 16),
        new THREE.MeshStandardMaterial({ color: n.color, emissive: n.color, emissiveIntensity: 1.8 })
      );
      nodeMesh.position.set(...n.pos);
      group.add(nodeMesh);

      const halo = new THREE.Mesh(
        new THREE.RingGeometry(0.26, 0.3, 24),
        new THREE.MeshBasicMaterial({ color: n.color, side: THREE.DoubleSide, transparent: true, opacity: 0.6 })
      );
      halo.position.set(...n.pos);
      group.add(halo);
    });

    // Flowing particles along splines
    const particleCount = 40;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleProgress = new Float32Array(particleCount);
    const particleCurveIndices = new Uint8Array(particleCount);

    for (let i = 0; i < particleCount; i++) {
      particleCurveIndices[i] = i % curves.length;
      particleProgress[i] = (i / particleCount);
    }

    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      size: 0.08,
      color: 0x00f6ff,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    group.add(particles);

    // Mouse tilt
    let mouseX = 0;
    let mouseY = 0;
    const onMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouseX = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
      mouseY = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
    };
    container.addEventListener('mousemove', onMouseMove);

    let animId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const delta = clock.getDelta();

      group.rotation.y = THREE.MathUtils.lerp(group.rotation.y, mouseX * 0.35, 0.05);
      group.rotation.x = THREE.MathUtils.lerp(group.rotation.x, -mouseY * 0.25, 0.05);

      coreMesh.rotation.y += delta * 0.6;
      coreMesh.rotation.x += delta * 0.3;
      ring1.rotation.z += delta * 0.5;
      ring2.rotation.y -= delta * 0.4;

      // Update particles
      const pos = particleGeo.attributes.position.array as Float32Array;
      for (let i = 0; i < particleCount; i++) {
        particleProgress[i] = (particleProgress[i] + delta * 0.18) % 1;
        const curve = curves[particleCurveIndices[i]];
        const pt = curve.getPoint(particleProgress[i]);
        pos[i * 3] = pt.x;
        pos[i * 3 + 1] = pt.y;
        pos[i * 3 + 2] = pt.z;
      }
      particleGeo.attributes.position.needsUpdate = true;

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      const w = container.clientWidth || 600;
      camera.aspect = w / height;
      camera.updateProjectionMatrix();
      renderer.setSize(w, height);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      container.removeEventListener('mousemove', onMouseMove);
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, []);

  return (
    <div className="hud-corner relative w-full h-[280px] bg-slate-950/80 border border-cyan-500/30 rounded-lg overflow-hidden backdrop-blur-xl flex items-center justify-center tech-grid-bg">
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
      <div className="pointer-events-none absolute top-3 left-4 flex items-center gap-2 font-mono text-[11px] text-cyan-300">
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
        <span className="tracking-widest font-bold">ORACLE // LIVING TOPOLOGY MESH</span>
      </div>
      <div className="pointer-events-none absolute bottom-3 right-4 flex items-center gap-4 font-mono text-[10px] text-slate-400">
        <span>6 SYNCHRONIZED CLUSTERS</span>
        <span>LATENCY: 1.4ms</span>
        <span className="text-emerald-400">● 100% OPERATIONAL</span>
      </div>
    </div>
  );
};
