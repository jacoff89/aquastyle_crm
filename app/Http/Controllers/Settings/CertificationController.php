<?php

namespace App\Http\Controllers\Settings;

use App\Events\Settings\CertificationCreated;
use App\Events\Settings\CertificationUpdated;
use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\StoreCertificationRequest;
use App\Http\Requests\Settings\UpdateCertificationRequest;
use App\Models\Certification;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

class CertificationController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', Certification::class);

        return Inertia::render('settings/certifications/Index', [
            'certifications' => Certification::query()->withCount('clients')->ordered()->get()
                ->map(fn (Certification $certification): array => [
                    'id' => $certification->id,
                    'name' => $certification->name,
                    'isActive' => $certification->is_active,
                    'clientsCount' => $certification->clients_count,
                ]),
        ]);
    }

    public function store(StoreCertificationRequest $request): RedirectResponse
    {
        $certification = Certification::create($request->validated());

        CertificationCreated::dispatch($certification, $request->user());

        return back()->with('status', "Сертификация «{$certification->name}» добавлена.");
    }

    public function update(UpdateCertificationRequest $request, Certification $certification): RedirectResponse
    {
        $certification->update($request->validated());
        CertificationUpdated::dispatchChanges($certification, $request->user());

        $status = match (true) {
            $certification->wasChanged('name') => "Сертификация переименована в «{$certification->name}».",
            $certification->wasChanged('is_active') && $certification->is_active => "Сертификация «{$certification->name}» снова доступна для выбора.",
            $certification->wasChanged('is_active') => "Сертификация «{$certification->name}» скрыта: у кого она уже есть, она останется, но выбрать её заново нельзя.",
            default => null,
        };

        return back()->with('status', $status);
    }
}
