<?php

namespace App\Http\Controllers;

use App\Events\Communications\CommunicationCreated;
use App\Events\Communications\CommunicationDeleted;
use App\Events\Communications\CommunicationUpdated;
use App\Http\Requests\Communications\StoreCommunicationRequest;
use App\Http\Requests\Communications\UpdateCommunicationRequest;
use App\Models\Client;
use App\Models\Communication;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

/**
 * Communications are kept on the client's card, so every action sends the person back to it.
 */
class ClientCommunicationController extends Controller
{
    public function store(StoreCommunicationRequest $request, Client $client): RedirectResponse
    {
        $communication = new Communication($request->validated());
        $communication->client()->associate($client);
        $communication->creator()->associate($request->user());
        $communication->save();

        CommunicationCreated::dispatch($communication, $request->user());

        return redirect()->route('clients.show', $client)->with('status', 'Коммуникация добавлена.');
    }

    public function update(UpdateCommunicationRequest $request, Communication $communication): RedirectResponse
    {
        $communication->update($request->validated());

        CommunicationUpdated::dispatchChanges($communication, $request->user());

        return redirect()->route('clients.show', $communication->client_id)->with('status', 'Изменения сохранены.');
    }

    public function destroy(Request $request, Communication $communication): RedirectResponse
    {
        Gate::authorize('delete', $communication);

        $communication->delete();

        CommunicationDeleted::dispatchFor($communication, $request->user());

        return redirect()->route('clients.show', $communication->client_id)->with('status', 'Коммуникация удалена.');
    }
}
