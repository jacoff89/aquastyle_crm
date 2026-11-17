<?php

namespace App\Models;

use App\Models\Concerns\HasListPosition;
use Database\Factories\CertificationFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * A certification a client holds, e.g. «Дайвер» or «Сухой костюм». A client may hold
 * several of them. Administrators maintain the list; a hidden certification can not be
 * newly given but stays on the clients who already hold it.
 */
#[Fillable(['name', 'is_active'])]
class Certification extends Model
{
    /** @use HasFactory<CertificationFactory> */
    use HasFactory, HasListPosition;

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'is_active' => true,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sort_order' => 'integer',
            'is_active' => 'boolean',
        ];
    }

    /**
     * The clients who hold this certification.
     *
     * @return BelongsToMany<Client, $this>
     */
    public function clients(): BelongsToMany
    {
        return $this->belongsToMany(Client::class);
    }

    /**
     * @param  Builder<Certification>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where('is_active', true);
    }
}
